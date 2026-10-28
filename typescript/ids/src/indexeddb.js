import { advanceWitnessPolicy } from './witness-policy.js';

const STORE = 'witness-policy';
const KEY = 'installed';
const RECORD = 'sociacl-witness-policy-installed-v1';

/** Browser-only durable storage. Configuration and origin storage are trust boundaries.
 * @param {{name: string, root: string, audience: string, minimumRevision: number,
 * now: () => number, indexedDB?: IDBFactory}} options
 */
export async function openWitnessPolicyStore(options) {
  // Copy trusted configuration: later mutation of the caller's object has no effect.
  const { name, root, audience, minimumRevision, now } = options;
  if (typeof name !== 'string' || !name || typeof root !== 'string' ||
      typeof audience !== 'string' || !audience ||
      !Number.isSafeInteger(minimumRevision) || minimumRevision < 1 || typeof now !== 'function') {
    throw Error('Invalid witness policy configuration');
  }
  const factory = options.indexedDB ?? globalThis.indexedDB;
  if (!factory) throw Error('IndexedDB unavailable');
  const db = await new Promise((resolve, reject) => {
    const request = factory.open(name, 1);
    let abandoned = false;
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onerror = () => reject(request.error ?? Error('Policy database open failed'));
    request.onblocked = () => {
      abandoned = true;
      reject(Error('Policy database upgrade blocked'));
    };
    request.onsuccess = () => {
      if (abandoned) request.result.close();
      else resolve(request.result);
    };
  });
  db.onversionchange = () => db.close();

  /** @param {unknown} envelope @param {unknown} previous @param {number} time @param {number} [floor] */
  function advance(envelope, previous, time, floor = minimumRevision) {
    const result = advanceWitnessPolicy(envelope, previous, root, audience, floor, time);
    if (!result.ok) throw Error('Invalid witness policy or stored state');
    return result.value;
  }
  /** @param {unknown} record */
  function saved(record) {
    if (record === null || typeof record !== 'object' ||
        Object.keys(record).length !== 4 || !('type' in record) || record.type !== RECORD ||
        !('state' in record) || typeof record.state !== 'string' ||
        !('envelope' in record) || typeof record.envelope !== 'string' ||
        !('acceptedAt' in record) || typeof record.acceptedAt !== 'number') {
      throw Error('Missing or corrupt installed witness policy');
    }
    // Reauthenticate the saved registry at its trusted acceptance time. Transport
    // expiry does not retrospectively remove installed witness issuance windows.
    const state = advance(record.envelope, record.state, record.acceptedAt, 1);
    if (state.revision !== JSON.parse(record.state).revision) throw Error('Stored policy revision mismatch');
    return state;
  }
  /** @param {'read'|'bootstrap'|'refresh'} mode @param {string} [envelope]
   * @returns {Promise<import('./types.js').WitnessPolicyState>} */
  function transact(mode, envelope) {
    return new Promise((resolve, reject) => {
      const write = mode !== 'read';
      const tx = db.transaction(STORE, write ? 'readwrite' : 'readonly',
        write ? { durability: 'strict' } : undefined);
      // Refuse implementations which silently ignore strict durability.
      if (write && tx.durability !== 'strict') {
        tx.abort();
        reject(Error('Strict IndexedDB durability unavailable'));
        return;
      }
      /** @type {import('./types.js').WitnessPolicyState | undefined} */
      let candidate;
      /** @type {unknown} */
      let failure;
      /** @param {unknown} error */
      const abort = error => {
        failure = error;
        tx.abort();
      };
      tx.onabort = () => reject(failure ?? tx.error ?? Error('Policy transaction aborted'));
      tx.onerror = () => { /* The default request error aborts the transaction. */ };
      tx.oncomplete = () => {
        try {
          if (!candidate) throw Error('Policy transaction completed without state');
          // A slow commit may cross transport expiry. Do not expose expired input;
          // the caller can reconcile the committed row with read(), without reset.
          if (write) advance(envelope, JSON.stringify(candidate), now());
          resolve(candidate);
        } catch (error) { reject(error); }
      };
      const store = tx.objectStore(STORE);
      const get = store.get(KEY);
      get.onsuccess = () => {
        try {
          if (mode === 'read') {
            candidate = saved(get.result);
            if (candidate.revision < minimumRevision) throw Error('Installed policy below required floor');
            return;
          }
          if (mode === 'bootstrap' && get.result !== undefined) throw Error('Policy already installed');
          const previous = mode === 'bootstrap' ? null : JSON.stringify(saved(get.result));
          const acceptedAt = now();
          candidate = advance(envelope, previous, acceptedAt);
          const put = store.put({ type: RECORD, state: JSON.stringify(candidate), envelope, acceptedAt }, KEY);
          put.onsuccess = () => {
            try {
              // Still inside the write lock, immediately before allowing commit.
              advance(envelope, JSON.stringify(candidate), now());
            } catch (error) { abort(error); }
          };
        } catch (error) { abort(error); }
      };
    });
  }
  return Object.freeze({
    /** Read committed state. Missing/corrupt storage never bootstraps implicitly. */
    read: () => transact('read'),
    /** Explicit, independently authorized first installation. @param {string} envelope */
    bootstrap: envelope => transact('bootstrap', envelope),
    /** Replace only after validating the latest committed history. @param {string} envelope */
    refresh: envelope => transact('refresh', envelope),
    close: () => db.close(),
  });
}
