//! Unix durable native consumer. The private state directory is independent,
//! trusted local storage: never sync or restore it from untrusted ciphertext.
use std::{cell::Cell, fs::{self, File, OpenOptions, DirBuilder}, io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt}, path::{Path, PathBuf}};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sociacl_ids::{parse_principal_id, ResolutionContext};
use crate::{canonical, hexutil, vault_native, EncDiscError, LocalVaultEnvelope, LocalVaultFileStore,
    VaultFileHead, VaultSyncHead, VaultSyncHeadFloor, open_native_vault_head,
    vault_sync_head_floor, validate_vault_sync_successor};

fn storage<T>(_: T) -> EncDiscError { EncDiscError::VaultStorage }
struct Lock { path: PathBuf, directory: File }
impl Drop for Lock { fn drop(&mut self) { let _ = fs::remove_dir(&self.path); } }
struct Temporary(PathBuf);
impl Drop for Temporary { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }
#[derive(Clone, Debug, PartialEq, Eq)]
struct State { floor: VaultSyncHeadFloor, ciphertext: VaultFileHead, checked_at: u64 }
impl State {
    fn encode(&self, binding: &str) -> Vec<u8> {
        // No private head, principal, passphrase or key is written to this ledger.
        serde_json::to_vec(&json!({"v":1,"binding":binding,"revision":self.floor.revision,"digest":self.floor.digest,
            "itemId":self.ciphertext.item_id,"versionId":self.ciphertext.version_id,"ciphertextDigest":self.ciphertext.digest,
            "checkedAt":self.checked_at})).expect("fixed JSON fields")
    }
    fn decode(bytes: &[u8], binding: &str) -> Result<Self, EncDiscError> {
        let v: Value = serde_json::from_slice(bytes).map_err(storage)?;
        let m = v.as_object().ok_or(EncDiscError::VaultStorage)?;
        if m.len() != 8 || v["v"] != 1 || v["binding"] != binding { return Err(EncDiscError::VaultStorage); }
        let integer = |key: &str| -> Result<u64, EncDiscError> {
            let n = v[key].as_u64().ok_or(EncDiscError::VaultStorage)?;
            canonical::canonical_decimal(n).map_err(storage)?; Ok(n)
        };
        let digest = |key: &str| -> Result<String, EncDiscError> {
            let s = v[key].as_str().ok_or(EncDiscError::VaultStorage)?;
            canonical::require_digest_hex(s).map_err(storage)?; Ok(s.into())
        };
        let revision = integer("revision")?;
        if revision == 0 { return Err(EncDiscError::VaultStorage); }
        Ok(Self { floor: VaultSyncHeadFloor { revision, digest: digest("digest")? },
            ciphertext: VaultFileHead { item_id: digest("itemId")?, version_id: digest("versionId")?, digest: digest("ciphertextDigest")? },
            checked_at: integer("checkedAt")? })
    }
}

/// One owner/vault's native head consumer. Two distinct private directories are
/// required, with trusted parents. A whole-device or trusted-ledger rollback is
/// outside this boundary, just as origin-wide rollback is outside browser IDB.
pub struct NativeVaultCustody {
    ciphertext: LocalVaultFileStore, root: PathBuf, device: u64, inode: u64, uid: u32, owner: String, vault: String, binding: String, create: Cell<bool>,
}
impl NativeVaultCustody {
    /// `create` creates both directories exclusively; it never repairs missing
    /// state in an existing installation. Initialization needs an external anchor.
    pub fn open(ciphertext_root: impl AsRef<Path>, state_root: impl AsRef<Path>, owner: &str, vault: &str,
        create: bool) -> Result<Self, EncDiscError> {
        parse_principal_id(owner).map_err(storage)?;
        canonical::require_digest_hex(vault).map_err(storage)?;
        let binding = canonical::sha256_hex(&canonical::length_prefixed(&["sociacl-native-vault-state-v1",owner,vault])?);
        let state_path = state_root.as_ref();
        if create { DirBuilder::new().mode(0o700).create(state_path).map_err(storage)?; }
        let state = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state_path).map_err(storage)?;
        let sm = state.metadata().map_err(storage)?;
        if !sm.is_dir() || sm.mode() & 0o7777 != 0o700 { return Err(EncDiscError::VaultStorage); }
        let root = fs::canonicalize(state_path).map_err(storage)?;
        if create {
            // Persist directory enrollment before accepting any committed state.
            let parent = state_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(parent).map_err(storage)?.sync_all().map_err(storage)?;
        }
        let ciphertext = LocalVaultFileStore::open(ciphertext_root.as_ref(), create)?;
        let cm = std::fs::metadata(ciphertext_root).map_err(storage)?;
        if cm.dev() == sm.dev() && cm.ino() == sm.ino() { return Err(EncDiscError::VaultStorage); }
        let store = Self { ciphertext, root, device: sm.dev(), inode: sm.ino(), uid: sm.uid(), owner: owner.into(), vault: vault.into(), binding, create: Cell::new(create) };
        if !create { let lock = store.lock()?; store.load(&lock)?; }
        Ok(store)
    }
    fn directory(&self) -> Result<File, EncDiscError> {
        let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&self.root).map_err(storage)?;
        let m = dir.metadata().map_err(storage)?;
        if !m.is_dir() || m.dev() != self.device || m.ino() != self.inode || m.uid() != self.uid || m.mode() & 0o7777 != 0o700 {
            return Err(EncDiscError::VaultStorage);
        }
        Ok(dir)
    }
    fn lock(&self) -> Result<Lock, EncDiscError> {
        let directory = self.directory()?;
        let path = self.root.join("head.lock");
        DirBuilder::new().mode(0o700).create(&path).map_err(storage)?;
        let lock = Lock { path, directory };
        self.directory()?;
        // Match the existing file adapter: a crash lock is never guessed stale or
        // automatically broken. Operators must reconcile it before reuse.
        Ok(lock)
    }
    fn load(&self, _lock: &Lock) -> Result<State, EncDiscError> {
        self.directory()?;
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.root.join("head.floor")).map_err(storage)?;
        let m = file.metadata().map_err(storage)?;
        if !m.is_file() || m.uid() != self.uid || m.mode() & 0o7777 != 0o600 || m.nlink() != 1 || m.len() > 2048 {
            return Err(EncDiscError::VaultStorage);
        }
        let mut bytes = Vec::new(); file.take(2049).read_to_end(&mut bytes).map_err(storage)?;
        if bytes.len() > 2048 { return Err(EncDiscError::VaultStorage); }
        State::decode(&bytes, &self.binding)
    }
    fn save(&self, lock: &Lock, state: &State) -> Result<(), EncDiscError> {
        self.directory()?;
        let mut random = [0u8; 16]; OsRng.fill_bytes(&mut random);
        let temporary = Temporary(self.root.join(format!(".{}.tmp", hexutil::encode_hex(&random))));
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW)
            .open(&temporary.0).map_err(storage)?;
        file.write_all(&state.encode(&self.binding)).map_err(storage)?;
        file.sync_all().map_err(storage)?;
        self.directory()?;
        fs::rename(&temporary.0, self.root.join("head.floor")).map_err(storage)?;
        lock.directory.sync_all().map_err(storage)?;
        // Failure after rename is ambiguous; exact prepared-byte retry reconciles.
        Ok(())
    }
    fn decrypt(&self, envelope: &LocalVaultEnvelope, password: &str) -> Result<VaultSyncHead, EncDiscError> {
        open_native_vault_head(envelope, &self.owner, &self.vault, password)
    }
    fn authenticate<'a, F>(&self, head: &VaultSyncHead, state: &State, rotations: &[Value], current: &mut F) -> Result<u64, EncDiscError>
        where F: FnMut() -> Result<ResolutionContext<'a>, EncDiscError> {
        vault_native::authenticate(head, &self.owner, &self.vault, &state.floor, state.checked_at, rotations, &current()?)
    }
    /// Explicit enrollment from an independently authenticated exact floor. Never
    /// derive `anchor` from a server download. Failed initial enrollment is not
    /// automatically repaired by reopening missing state.
    pub fn initialize<'a, F>(&self, envelope: &LocalVaultEnvelope, anchor: &VaultSyncHeadFloor, password: &str,
        rotations: &[Value], mut current: F) -> Result<VaultSyncHead, EncDiscError>
        where F: FnMut() -> Result<ResolutionContext<'a>, EncDiscError> {
        let lock = self.lock()?;
        let head = self.decrypt(envelope, password)?;
        let mut state = State { floor: anchor.clone(), ciphertext: VaultFileHead::for_envelope(envelope), checked_at: 0 };
        // Only ENOENT means uninitialized. Wrong mode, symlink, corrupt bytes etc.
        // must not silently reset the ledger.
        match fs::symlink_metadata(self.root.join("head.floor")) {
            Ok(_) => {
                let old = self.load(&lock)?;
                if old.floor != state.floor || old.ciphertext != state.ciphertext { return Err(EncDiscError::VaultStorage); }
                state.checked_at = old.checked_at;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.create.get() => {},
            Err(_) => return Err(EncDiscError::VaultStorage),
        }
        state.checked_at = self.authenticate(&head, &state, rotations, &mut current)?;
        self.ciphertext.write(envelope, None)?;
        self.ciphertext.read(&state.ciphertext)?;
        state.checked_at = self.authenticate(&head, &state, rotations, &mut current)?;
        self.create.set(false);
        self.save(&lock, &state)?;
        Ok(head)
    }
    /// Authenticate the current encrypted head against the durable independent
    /// floor. This returns metadata only, never item plaintext or Check authority.
    pub fn read<'a, F>(&self, password: &str, rotations: &[Value], mut current: F) -> Result<VaultSyncHead, EncDiscError>
        where F: FnMut() -> Result<ResolutionContext<'a>, EncDiscError> {
        let lock = self.lock()?;
        let mut state = self.load(&lock)?;
        let head = self.decrypt(&self.ciphertext.read(&state.ciphertext)?, password)?;
        state.checked_at = self.authenticate(&head, &state, rotations, &mut current)?;
        self.save(&lock, &state)?;
        Ok(head)
    }
    /// Commit a prepared successor after exact local ciphertext readback. Remote
    /// publication/readback remains the caller's prior responsibility. Retain the
    /// original envelope on ambiguous errors; a newly sealed retry is not exact.
    pub fn advance<'a, F>(&self, envelope: &LocalVaultEnvelope, expected: &VaultSyncHeadFloor, password: &str,
        rotations: &[Value], mut current: F) -> Result<VaultSyncHead, EncDiscError>
        where F: FnMut() -> Result<ResolutionContext<'a>, EncDiscError> {
        let lock = self.lock()?;
        let old = self.load(&lock)?;
        let head = self.decrypt(envelope, password)?;
        let mut next = State { floor: vault_sync_head_floor(&head)?, ciphertext: VaultFileHead::for_envelope(envelope), checked_at: old.checked_at };
        if old.floor == next.floor {
            if old.ciphertext != next.ciphertext { return Err(EncDiscError::VaultStorage); }
        } else {
            if old.floor != *expected { return Err(EncDiscError::VaultStorage); }
            let previous = self.decrypt(&self.ciphertext.read(&old.ciphertext)?, password)?;
            if vault_sync_head_floor(&previous)? != old.floor { return Err(EncDiscError::VaultRejected); }
            validate_vault_sync_successor(&previous, &head)?;
        }
        next.checked_at = self.authenticate(&head, &next, rotations, &mut current)?;
        self.ciphertext.write(envelope, None)?;
        self.ciphertext.read(&next.ciphertext)?;
        next.checked_at = self.authenticate(&head, &next, rotations, &mut current)?;
        self.save(&lock, &next)?;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_state_schema_binds_floor_ciphertext_and_namespace() {
        let state = State { floor: VaultSyncHeadFloor { revision: 2, digest: "12".repeat(32) },
            ciphertext: VaultFileHead { item_id: "23".repeat(32), version_id: "34".repeat(32), digest: "45".repeat(32) }, checked_at: 20 };
        let binding = "56".repeat(32);
        let bytes = state.encode(&binding);
        assert_eq!(State::decode(&bytes, &binding).unwrap(), state);
        assert!(State::decode(&bytes, &"67".repeat(32)).is_err());
        for patch in [json!({"v":2}), json!({"revision":0}), json!({"checkedAt":9_007_199_254_740_992u64}),
            json!({"itemId":"../outside"}), json!({"ciphertextDigest":"AB".repeat(32)}), json!({"extra":true})] {
            let mut value: Value = serde_json::from_slice(&bytes).unwrap();
            value.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
            assert!(State::decode(&serde_json::to_vec(&value).unwrap(), &binding).is_err());
        }
    }
}
