/**
 * In-place migration from plaintext MeshSeeGrant rows.
 *
 * s3r.ch copies docs/s3rch-check.d.ts and reimplements it. It does not
 * import this file and it does not import the Rust crate. SEA receipt
 * verification stays in the Rust reference. This module fails closed on
 * the structure: the version gate does not drop plaintext, one reader
 * does not clear another, and a wider window or an extra accessor is
 * rejected. A wrap named here is not a grant. Whether public-plain stays
 * is open. This module does not decide it.
 */
import type {
  GrantStorage,
  GunAclEdge,
  MeshSeeGrant,
  MigrationAdmission,
  MigrationAdmissionInput,
  SignedGrantPayload,
  WrappedKey,
} from "../../docs/s3rch-check.js";

function reject(): never {
  throw new Error("migration rejected");
}

function safe(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function isHex(value: string, length: number): boolean {
  return value.length === length && /^[0-9a-f]+$/.test(value);
}

function stated(value: number): 0 | 1 {
  if (value !== 0 && value !== 1) {
    reject();
  }
  return value;
}

type CurrentGrant = GunAclEdge;

function escapeKey(id: string, slash: boolean): string {
  return id.replace(slash ? /[~.#$[\]/]/g : /[~.#$[\]]/g, (ch) => {
    switch (ch) {
      case "~":
        return "~0";
      case ".":
        return "~1";
      case "#":
        return "~2";
      case "$":
        return "~3";
      case "[":
        return "~4";
      case "]":
        return "~5";
      case "/":
        return "~6";
      default:
        return ch;
    }
  });
}

function asciiTrim(text: string): string {
  let start = 0;
  let end = text.length;
  const space = (code: number) =>
    code === 0x09 || code === 0x0a || code === 0x0b || code === 0x0c || code === 0x0d || code === 0x20;
  while (start < end && space(text.charCodeAt(start))) start += 1;
  while (end > start && space(text.charCodeAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

function aclKey(id: string): string {
  return escapeKey(asciiTrim(id), true);
}

function hasUnpairedSurrogate(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function barePrincipal(id: string): string | null {
  if (id.length === 0 || id === "." || id === ".." || id === "..." || id.includes(".get(") || id.includes(" ")) return null;
  if (hasUnpairedSurrogate(id)) return null;
  if ([...id].length > 256) return null;
  if (/[/#$[\]~]/.test(id)) return null;
  if (/\p{Z}|\p{Cf}/u.test(id)) return null;
  for (let i = 0; i < id.length; i += 1) {
    const code = id.charCodeAt(i);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return null;
  }
  return id;
}

function aclPrincipalKey(id: string): string | null {
  if (hasUnpairedSurrogate(id)) return null;
  const trimmed = asciiTrim(id);
  if (trimmed.length === 0 || trimmed.includes(".get(")) return null;
  const parts = trimmed
    .split("/")
    .map((part) => asciiTrim(part))
    .filter((part) => part.length > 0);
  if (parts.length === 3 && parts[0] === "s3rch" && parts[1] === "users") {
    return barePrincipal(parts[2] ?? "");
  }
  if (trimmed.includes("/")) return null;
  return barePrincipal(trimmed);
}

function grantSoul(owner: string, object: string, accessor: string): string | null {
  const ownerKey = aclPrincipalKey(owner);
  const accessorKey = aclPrincipalKey(accessor);
  if (ownerKey == null || accessorKey == null) return null;
  return `s3rch/acl/${ownerKey}/${aclKey(object)}/${accessorKey}`;
}

function currentGrants(input: MigrationAdmissionInput): CurrentGrant[] {
  const seen: string[] = [];
  const current: CurrentGrant[] = [];
  for (const edge of input.grants) {
    const grant = edge.grant;
    if (
      edge.owner !== input.owner ||
      grant.object !== input.migration.object ||
      grant.accessor.length === 0 ||
      grantSoul(input.owner, input.migration.object, grant.accessor) == null ||
      edge.soul !== grantSoul(input.owner, input.migration.object, grant.accessor) ||
      !safe(edge.hamState) ||
      !safe(grant.from) ||
      !safe(grant.until) ||
      seen.includes(grant.accessor)
    ) {
      reject();
    }
    seen.push(grant.accessor);
    const rowStated = stated(grant.stated);
    if (rowStated === 0) {
      if (edge.hamState === 0) {
        reject();
      }
      continue;
    }
    if (grant.from >= grant.until) {
      reject();
    }
    if (input.now < grant.until) {
      current.push(edge);
    }
  }
  current.sort((left, right) => left.grant.accessor.localeCompare(right.grant.accessor));
  return current;
}

function bump(hamState: number): number {
  if (!safe(hamState) || !safe(hamState + 1)) {
    reject();
  }
  return hamState + 1;
}

function names(grants: readonly CurrentGrant[]): string[] {
  return grants.map((edge) => edge.grant.accessor).sort((left, right) => left.localeCompare(right));
}

function skipPublic(input: MigrationAdmissionInput, current: readonly CurrentGrant[]): MigrationAdmission {
  if (
    input.migration.readers.length !== 0 ||
    input.migration.rewrapped.length !== 0 ||
    input.payloads.length !== 0 ||
    input.receipts.length !== 0 ||
    input.readerVersions.length !== 0
  ) {
    reject();
  }
  return {
    object: input.migration.object,
    plaintextRetained: names(current),
    plaintextDropped: [],
    soulReplaced: false,
    soulHamState: input.soulHamState,
    cancelled: [],
    skippedPublic: true,
    ciphertextPublished: false,
    grantsSee: false,
    delaysPrivilegeDown: false,
    widened: false,
    historicalReplicaRemains: true,
  };
}

function alignReaders(input: MigrationAdmissionInput, current: readonly CurrentGrant[]): void {
  if (input.migration.readers.length !== current.length || input.readerVersions.length !== current.length) {
    reject();
  }
  const readers = [...input.migration.readers].sort((left, right) =>
    left.accessor.localeCompare(right.accessor),
  );
  const versions = [...input.readerVersions].sort((left, right) =>
    left.accessor.localeCompare(right.accessor),
  );
  const epubs: string[] = [];
  for (let index = 0; index < current.length; index += 1) {
    const reader = readers[index];
    const version = versions[index];
    const grant = current[index];
    if (
      reader === undefined ||
      version === undefined ||
      grant === undefined ||
      reader.accessor !== grant.grant.accessor ||
      version.accessor !== grant.grant.accessor ||
      !safe(version.version) ||
      version.epub.length === 0 ||
      epubs.includes(version.epub)
    ) {
      reject();
    }
    epubs.push(version.epub);
    const atGate = version.version >= input.migration.versionGate;
    if (reader.atGate !== atGate) {
      reject();
    }
  }
}

function alignReceipts(input: MigrationAdmissionInput, current: readonly CurrentGrant[]): void {
  const seen: string[] = [];
  for (const receipt of input.receipts) {
    if (
      receipt.accessor.length === 0 ||
      seen.includes(receipt.accessor) ||
      !current.some((edge) => edge.grant.accessor === receipt.accessor) ||
      !isHex(receipt.signature, 128)
    ) {
      reject();
    }
    seen.push(receipt.accessor);
  }
  for (const reader of input.migration.readers) {
    const matched = input.receipts.filter((receipt) => receipt.accessor === reader.accessor).length;
    const expected = reader.acknowledged ? 1 : 0;
    if (matched !== expected) {
      reject();
    }
  }
}

function alignPayloads(input: MigrationAdmissionInput, current: readonly CurrentGrant[]): number | undefined {
  if (input.payloads.length !== current.length) {
    reject();
  }
  if (current.length === 0) {
    return undefined;
  }
  let epoch: number | undefined;
  let digest: string | undefined;
  for (const edge of current) {
    const payload = input.payloads.find((row) => row.accessor === edge.grant.accessor);
    if (payload === undefined) {
      reject();
    }
    if (
      !safe(payload.from) ||
      !safe(payload.until) ||
      !safe(payload.epoch) ||
      !safe(payload.grantRevision) ||
      payload.object !== edge.grant.object ||
      payload.owner !== input.owner ||
      payload.from !== edge.grant.from ||
      payload.until !== edge.grant.until ||
      payload.stated !== 1 ||
      edge.grant.stated !== 1 ||
      payload.grantRevision === 0 ||
      !isHex(payload.itemCiphertextDigest, 64)
    ) {
      reject();
    }
    if (epoch === undefined) {
      epoch = payload.epoch;
    } else if (epoch !== payload.epoch) {
      reject();
    }
    if (digest === undefined) {
      digest = payload.itemCiphertextDigest;
    } else if (digest !== payload.itemCiphertextDigest) {
      reject();
    }
  }
  return epoch;
}

function wrapShape(wrap: WrappedKey, object: string): void {
  if (
    wrap.scope !== "item-dek" ||
    wrap.target !== "reader-epub" ||
    wrap.object !== object ||
    (wrap.group !== undefined && wrap.group.length !== 0) ||
    wrap.wrappedKey.length === 0 ||
    !/^[0-9a-f]+$/.test(wrap.wrappedKey) ||
    !isHex(wrap.revisionId, 64) ||
    !safe(wrap.epoch)
  ) {
    reject();
  }
}

function alignWraps(input: MigrationAdmissionInput, epoch: number | undefined): void {
  if (input.migration.rewrapped.length !== input.readerVersions.length) {
    reject();
  }
  const versions = [...input.readerVersions].sort((left, right) =>
    left.accessor.localeCompare(right.accessor),
  );
  let revision: string | undefined;
  const seen: string[] = [];
  for (const version of versions) {
    const wrap = input.migration.rewrapped.find((row) => row.targetId === version.epub);
    if (wrap === undefined || seen.includes(wrap.targetId)) {
      reject();
    }
    seen.push(wrap.targetId);
    wrapShape(wrap, input.migration.object);
    if (epoch !== undefined && wrap.epoch !== epoch) {
      reject();
    }
    if (revision === undefined) {
      revision = wrap.revisionId;
    } else if (revision !== wrap.revisionId) {
      reject();
    }
  }
}

function finish(input: MigrationAdmissionInput, current: readonly CurrentGrant[]): MigrationAdmission {
  const dropped: string[] = [];
  const retained: string[] = [];
  for (const reader of input.migration.readers) {
    if (reader.acknowledged) {
      dropped.push(reader.accessor);
    } else {
      retained.push(reader.accessor);
    }
  }
  dropped.sort((left, right) => left.localeCompare(right));
  retained.sort((left, right) => left.localeCompare(right));
  if (retained.length === 0) {
    const cancelled: GunAclEdge[] = current.map((edge) => {
      const grant: MeshSeeGrant = { ...edge.grant, stated: 0 };
      return {
        soul: edge.soul,
        owner: edge.owner,
        grant,
        hamState: bump(edge.hamState),
      };
    });
    return {
      object: input.migration.object,
      plaintextRetained: retained,
      plaintextDropped: dropped,
      soulReplaced: true,
      soulHamState: bump(input.soulHamState),
      cancelled,
      skippedPublic: false,
      ciphertextPublished: true,
      grantsSee: false,
      delaysPrivilegeDown: false,
      widened: false,
      historicalReplicaRemains: true,
    };
  }
  return {
    object: input.migration.object,
    plaintextRetained: retained,
    plaintextDropped: dropped,
    soulReplaced: false,
    soulHamState: input.soulHamState,
    cancelled: [],
    skippedPublic: false,
    ciphertextPublished: true,
    grantsSee: false,
    delaysPrivilegeDown: false,
    widened: false,
    historicalReplicaRemains: true,
  };
}

/**
 * Structural privilege check. The version gate does not drop plaintext.
 * Returns an admission that does not grant.
 */
export function applyProtocolMigration(input: MigrationAdmissionInput): MigrationAdmission {
  if (
    input.caller.length === 0 ||
    input.owner.length === 0 ||
    input.caller !== input.owner ||
    input.migration.object.length === 0
  ) {
    reject();
  }
  const objects = new Set(input.grants.map((edge) => edge.grant.object));
  if (objects.size > 1 || (objects.size === 1 && !objects.has(input.migration.object))) {
    reject();
  }
  if (
    !safe(input.now) ||
    !safe(input.migration.fromVersion) ||
    !safe(input.migration.toVersion) ||
    !safe(input.migration.versionGate) ||
    !safe(input.soulHamState) ||
    input.migration.fromVersion >= input.migration.toVersion
  ) {
    reject();
  }
  const storage: GrantStorage = input.storage;
  if (storage !== "public-plain" && storage !== "private-row") {
    reject();
  }
  const current = currentGrants(input);
  if (storage === "public-plain") {
    return skipPublic(input, current);
  }
  alignReaders(input, current);
  alignReceipts(input, current);
  const epoch = alignPayloads(input, current);
  alignWraps(input, epoch);
  return finish(input, current);
}

export function migrationGrantsSee(admission: MigrationAdmission): false {
  return admission.grantsSee;
}
