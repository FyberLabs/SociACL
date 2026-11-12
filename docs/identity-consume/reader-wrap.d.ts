import type { Result, ItemReaderWrap } from './types.js';
/** Requires a current authorized named set. A wrap is not a grant. Maximum 64
 * readers, each {account,pub,identityPub,epub}; pub must match identityPub. */
export declare function wrapItemDekToReaders(dek: Uint8Array, context: unknown, readers: unknown, named: unknown): Promise<Result<readonly ItemReaderWrap[]>>;
/** expected is the current authorized {epoch,object,revisionId}. Raw routing
 * metadata must remain confidential. Check and fresh epoch status are separate. */
export declare function openItemDekReaderWrap(input: unknown, epriv: string, epub: string, expected: unknown): Promise<Result<Uint8Array>>;
