//! Unix local ciphertext adapter. Private directory, no-follow opens, CAS and fsync.
//! The caller owns the trusted head ledger; this adapter is not rollback authority.
use std::{fs::{self, File, OpenOptions, DirBuilder}, io::{Read, Write}, path::{Path, PathBuf}};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use rand::{rngs::OsRng, RngCore};
use crate::{EncDiscError, LocalVaultEnvelope, VAULT_LOCAL_MAX_BYTES};
use crate::{canonical, hexutil};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultFileHead { pub item_id: String, pub version_id: String, pub digest: String }
impl VaultFileHead {
    pub fn for_envelope(envelope: &LocalVaultEnvelope) -> Self {
        Self { item_id: envelope.item_id(), version_id: envelope.version_id(), digest: canonical::sha256_hex(envelope.bytes()) }
    }
}
pub struct LocalVaultFileStore { root: PathBuf, device: u64, inode: u64, owner: u32 }
struct Lock(PathBuf);
impl Drop for Lock { fn drop(&mut self) { let _ = fs::remove_dir(&self.0); } }
struct Temporary(PathBuf);
impl Drop for Temporary { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }
fn storage<T>(_: T) -> EncDiscError { EncDiscError::VaultStorage }
fn id(text: &str) -> Result<(), EncDiscError> {
    if text.len() != 64 { return Err(EncDiscError::VaultStorage); }
    hexutil::decode_hex(text).map(|_| ()).map_err(storage)
}
impl LocalVaultFileStore {
    /// Explicitly create an empty private directory, or open an existing one.
    /// Parents must already be trusted. No recursive creation or permission repair.
    pub fn open(path: impl AsRef<Path>, create: bool) -> Result<Self, EncDiscError> {
        let path = path.as_ref();
        if create { DirBuilder::new().mode(0o700).create(path).map_err(storage)?; }
        let metadata = fs::symlink_metadata(path).map_err(storage)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o7777 != 0o700 { return Err(EncDiscError::VaultStorage); }
        Ok(Self { root: fs::canonicalize(path).map_err(storage)?, device: metadata.dev(), inode: metadata.ino(), owner: metadata.uid() })
    }
    fn directory(&self) -> Result<File, EncDiscError> {
        let directory = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY).open(&self.root).map_err(storage)?;
        let m = directory.metadata().map_err(storage)?;
        if !m.is_dir() || m.dev() != self.device || m.ino() != self.inode || m.uid() != self.owner || m.mode() & 0o7777 != 0o700 { return Err(EncDiscError::VaultStorage); }
        Ok(directory)
    }
    fn path(&self, item: &str) -> Result<PathBuf, EncDiscError> { id(item)?; Ok(self.root.join(format!("{item}.vault"))) }
    fn load(&self, item: &str) -> Result<Option<LocalVaultEnvelope>, EncDiscError> {
        let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(self.path(item)?) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(storage(e)),
        };
        let m = file.metadata().map_err(storage)?;
        if !m.is_file() || m.uid() != self.owner || m.mode() & 0o7777 != 0o600 || m.nlink() != 1 || m.len() > VAULT_LOCAL_MAX_BYTES as u64 { return Err(EncDiscError::VaultStorage); }
        let mut bytes = Vec::new(); file.take((VAULT_LOCAL_MAX_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(storage)?;
        let envelope = LocalVaultEnvelope::from_bytes(bytes).map_err(storage)?;
        if envelope.item_id() != item { return Err(EncDiscError::VaultStorage); }
        Ok(Some(envelope))
    }
    /// Missing state, unexpected bytes and rollback below the caller's trusted head
    /// all fail. Never obtain the expected head from the same untrusted file.
    pub fn read(&self, expected: &VaultFileHead) -> Result<LocalVaultEnvelope, EncDiscError> {
        self.directory()?; id(&expected.item_id)?; id(&expected.version_id)?; id(&expected.digest)?;
        let envelope = self.load(&expected.item_id)?.ok_or(EncDiscError::VaultStorage)?;
        if VaultFileHead::for_envelope(&envelope) != *expected { return Err(EncDiscError::VaultStorage); }
        Ok(envelope)
    }
    /// Compare-and-swap whole encrypted snapshots. None means create-only. Exact
    /// ciphertext retries reconcile a lost successful response without overwriting.
    /// A crash can leave a lock directory; it is never guessed stale or auto-broken.
    /// Errors after rename are ambiguous: reconcile against the candidate head.
    pub fn write(&self, envelope: &LocalVaultEnvelope, expected: Option<&VaultFileHead>) -> Result<VaultFileHead, EncDiscError> {
        let directory = self.directory()?;
        let next = VaultFileHead::for_envelope(envelope);
        let lock_path = self.root.join(format!("{}.lock", next.item_id));
        DirBuilder::new().mode(0o700).create(&lock_path).map_err(storage)?;
        let _lock = Lock(lock_path);
        let current = self.load(&next.item_id)?;
        if current.as_ref().map(VaultFileHead::for_envelope).as_ref() == Some(&next) {
            // Reconcile a prior ambiguous rename only after confirming durability.
            OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(self.path(&next.item_id)?).map_err(storage)?.sync_all().map_err(storage)?;
            directory.sync_all().map_err(storage)?;
            return Ok(next);
        }
        match (current.as_ref(), expected) {
            (None, None) => {},
            (Some(current), Some(head)) if VaultFileHead::for_envelope(current) == *head => {},
            _ => return Err(EncDiscError::VaultStorage),
        }
        let mut random = [0u8;16]; OsRng.fill_bytes(&mut random);
        let path = self.root.join(format!(".{}.tmp", hexutil::encode_hex(&random)));
        let temporary = Temporary(path.clone());
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&path).map_err(storage)?;
        file.write_all(envelope.bytes()).map_err(storage)?; file.sync_all().map_err(storage)?;
        self.directory()?;
        fs::rename(&path, self.path(&next.item_id)?).map_err(storage)?;
        directory.sync_all().map_err(storage)?;
        drop(temporary);
        Ok(next)
    }
}
