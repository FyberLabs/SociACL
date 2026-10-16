/**
 * Inbox lane scan for the encrypted-discovery contract.
 *
 * s3r.ch copies docs/s3rch-check.d.ts and reimplements it. It does not
 * import this file and it does not import the Rust crate. This module
 * dedups a daily shard by entry id. It does not admit a row, it does
 * not grant, and it does not implement a shard-close watermark.
 */

export const INBOX_ENTRY_MAX_BYTES = 65536;

/** A per-device cursor is not part of this contract. */
export function shardScanUsesDeviceCursor(): boolean {
  return false;
}

/** Issue #22 defers a trusted shard-close watermark. */
export function shardCloseWatermarkImplemented(): boolean {
  return false;
}

/** An admitted append does not make Check allow. */
export function appendGrantsSee(): boolean {
  return false;
}

/** Devices of one account share that account's one lane. */
export function lanesPerDevice(): boolean {
  return false;
}

function isLeap(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

export function isUtcDay(day: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!match) {
    return false;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const dom = Number(match[3]);
  let max = 0;
  if (month === 2) {
    max = isLeap(year) ? 29 : 28;
  } else if ([4, 6, 9, 11].includes(month)) {
    max = 30;
  } else if ([1, 3, 5, 7, 8, 10, 12].includes(month)) {
    max = 31;
  }
  return dom >= 1 && dom <= max;
}

/**
 * Rescan one UTC day. Dedup by entry id against `seen` and within the
 * shard. A later call with the whole shard still returns a new id.
 */
export function scanDailyShardIds(
  day: string,
  seen: readonly string[],
  shard: readonly string[],
): string[] {
  if (!isUtcDay(day)) {
    throw new Error("inbox rejected");
  }
  const have = new Set(seen);
  const fresh: string[] = [];
  for (const id of shard) {
    if (have.has(id)) {
      continue;
    }
    have.add(id);
    fresh.push(id);
  }
  return fresh;
}
