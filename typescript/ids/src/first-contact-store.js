import { parsePrincipalId } from './ids.js';

/** @typedef {{channelId:string,revision:number,encryptionEpub:string,expiresAt:number,maxLifetimeSeconds:number,maxMessageBytes:number}} Descriptor */
/** @typedef {{replayKey:string,requestId:string,replayUntil:number,expiresAt:number,envelope:Uint8Array}} Reservation */
/** @typedef {{ciphertextHex:string,rotationSeq:number}} Grant */
/** @typedef {Reservation & {revision:number,status:'pending'|'accepted'|'rejected'|'delivered',grant?:Grant}} Row */
/** @typedef {{v:1,owner:string,revision:number,clock:number,enabled:boolean,descriptor:Descriptor|null,rows:Record<string,Row>}} State */
/** @typedef {{status:'rejected'}|({status:'accepted'} & Grant)} Decision */
const STORE = 'first-contact';
const MAX_ROWS = 256;
const MAX_SECONDS = 7 * 86400;
/** @param {unknown} s @param {number} n */
const hex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/.test(s);
/** @param {number} n */
const integer = n => Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0);
/** @template T @param {T} value @returns {T} */
const clone = value => structuredClone(value);

/** Durable recipient-owned replay and decision journal. It stores ciphertext only.
 * Cryptographic authentication belongs to the caller before reserve and decide.
 * Clearing origin storage is destructive: reconnect fails until explicit bootstrap,
 * and bootstrap must publish the freshly generated channel, never reuse an old one.
 * @param {{name:string, owner:string, now:()=>number, create?:boolean, indexedDB?:IDBFactory}} options
 */
export async function openFirstContactStore(options) {
  const { name, owner, now, create = false } = options;
  const principal = parsePrincipalId(owner);
  if (!name || !principal.ok || principal.value !== owner || typeof now !== 'function') throw Error('Invalid inbox configuration');
  const factory = options.indexedDB ?? globalThis.indexedDB;
  if (!factory) throw Error('IndexedDB unavailable');
  /** @type {IDBDatabase} */
  const db = await new Promise((resolve, reject) => {
    const request = factory.open(name, 1); let abandoned = false;
    request.onupgradeneeded = () => {
      if (!create) { request.transaction?.abort(); return; }
      request.result.createObjectStore(STORE);
    };
    request.onblocked = () => { abandoned = true; reject(Error('Inbox database blocked')); };
    request.onerror = () => reject(request.error ?? Error('Inbox database unavailable'));
    request.onsuccess = () => { if (abandoned) request.result.close(); else resolve(request.result); };
  });
  db.onversionchange = () => db.close();

  function time() { const t = now(); if (!integer(t)) throw Error('Invalid clock'); return t; }
  /** @param {Omit<Descriptor,"channelId"|"revision">} input @param {number} t */
  function policy(input, t) {
    if (!input || !parsePrincipalId(input.encryptionEpub).ok ||
        !integer(input.expiresAt) || input.expiresAt <= t || input.expiresAt - t > MAX_SECONDS ||
        !integer(input.maxLifetimeSeconds) || input.maxLifetimeSeconds < 1 || input.maxLifetimeSeconds > MAX_SECONDS ||
        !integer(input.maxMessageBytes) || input.maxMessageBytes < 1 || input.maxMessageBytes > 4096) throw Error('Invalid descriptor policy');
    return { encryptionEpub: input.encryptionEpub, expiresAt: input.expiresAt,
      maxLifetimeSeconds: input.maxLifetimeSeconds, maxMessageBytes: input.maxMessageBytes };
  }
  /** @param {State} state @param {Descriptor|null} descriptor @param {number} t */
  function match(state, descriptor, t) {
    const active = state.descriptor;
    if (!state.enabled || !active || t >= active.expiresAt ||
        !descriptor || Object.keys(descriptor).length !== 6 ||
        ['channelId','revision','encryptionEpub','expiresAt','maxLifetimeSeconds','maxMessageBytes'].some(key => Reflect.get(descriptor, key) !== Reflect.get(active, key))) throw Error('Inactive or changed request channel');
  }
  // A single readwrite transaction serializes all tabs for this recipient. Resolve
  // only on completion, never on request success; abort/quota errors expose no row.
  /** @template T @param {(state:State,t:number)=>T} change @param {boolean} [allowMissing] @returns {Promise<T>} */
  function transaction(change, allowMissing = false) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite', { durability: 'strict' });
      /** @type {T} */ let output;
      /** @type {unknown} */ let failure;
      tx.onabort = () => reject(failure ?? tx.error ?? Error('Inbox transaction aborted'));
      tx.onerror = () => {};
      tx.oncomplete = () => resolve(output);
      if (tx.durability !== 'strict') { failure = Error('Strict durability unavailable'); tx.abort(); return; }
      const store = tx.objectStore(STORE), read = store.get(owner);
      read.onsuccess = () => {
        try {
          const t = time();
          /** @type {State} */ let state = read.result;
          if (!state) {
            if (!allowMissing) throw Error('Missing inbox state; explicit new channel required');
            state = { v: 1, owner, revision: 0, clock: t, enabled: false, descriptor: null, rows: {} };
          }
          if (state.v !== 1 || state.owner !== owner || !integer(state.revision) ||
              !integer(state.clock) || state.clock > t || !state.rows || Array.isArray(state.rows) ||
              Object.keys(state.rows).length > MAX_ROWS) throw Error('Corrupt inbox or clock rollback');
          state.clock = t;
          for (const [key, row] of Object.entries(state.rows)) {
            if (!hex(key, 64) || !integer(row.replayUntil)) throw Error('Corrupt replay row');
            if (row.replayUntil <= t && row.status !== 'accepted') delete state.rows[key];
          }
          output = change(state, t);
          store.put(state, owner);
        } catch (error) { failure = error; tx.abort(); }
      };
    });
  }
  return Object.freeze({
    owner,
    /** Explicit recipient opt-in/rotation. Always generates an unrelated public id.
     * This descriptor must be advertised through an authenticated recipient channel.
     * @param {Omit<Descriptor,"channelId"|"revision">} input
     */
    activate(input) {
      const proposed = clone(input);
      const channelId = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
      return transaction((state, t) => {
        const p = policy(proposed, t);
        if (state.revision >= Number.MAX_SAFE_INTEGER) throw Error('Descriptor revision exhausted');
        state.revision++; state.enabled = true;
        state.descriptor = { channelId, revision: state.revision, ...p };
        return clone(state.descriptor);
      }, create);
    },
    disable: () => transaction(state => { state.enabled = false; }),
    descriptor: () => transaction((state, t) => { match(state, state.descriptor, t); if (!state.descriptor) throw Error('Missing descriptor'); return clone(state.descriptor); }),
    /** Only authenticated requests may be submitted. A duplicate never updates its
     * ciphertext, decision or retention. Reservations live through descriptor expiry.
     */
    /** @param {Descriptor} descriptor @param {Reservation} record */
    reserve(descriptor, record) {
      const d = clone(descriptor), r = clone(record);
      return transaction((state, t) => {
        match(state, d, t);
        if (!r || !hex(r.replayKey, 64) || !hex(r.requestId, 64) || r.replayUntil !== d.expiresAt ||
            !integer(r.expiresAt) || r.expiresAt <= t || r.expiresAt > r.replayUntil ||
            !(r.envelope instanceof Uint8Array) || r.envelope.length < 94 || r.envelope.length > 8192) throw Error('Invalid reservation');
        if (Object.hasOwn(state.rows, r.replayKey)) return false;
        if (Object.keys(state.rows).length >= MAX_ROWS) throw Error('Inbox quota exceeded');
        state.rows[r.replayKey] = { replayKey:r.replayKey,requestId:r.requestId,replayUntil:r.replayUntil,
          expiresAt:r.expiresAt,envelope:r.envelope,revision:d.revision,status:'pending' };
        return true;
      });
    },
    pending: () => transaction((state, t) => {
      match(state, state.descriptor, t);
      return clone(Object.values(state.rows).filter(row => row.revision === state.revision && row.status === 'pending' && row.expiresAt > t));
    }),
    /** Explicit user decision after re-opening and authenticating the stored request.
     * Accepted ciphertext is an outbox entry: publish only after this commit succeeds.
     * Conflicting/repeated decisions fail; callers reconcile with outbox(), not reseal.
     */
    /** @param {Descriptor} descriptor @param {string} replayKey @param {string} requestId @param {Decision} decision */
    decide(descriptor, replayKey, requestId, decision) {
      const d = clone(descriptor), selected = clone(decision);
      return transaction((state, t) => {
        match(state, d, t);
        const row = state.rows[replayKey];
        if (!hex(replayKey, 64) || !hex(requestId, 64) || !row || row.requestId !== requestId ||
            row.revision !== state.revision || row.status !== 'pending' || row.expiresAt <= t) throw Error('Request is not pending');
        if (selected?.status === 'accepted') {
          if (!integer(selected.rotationSeq) || !hex(selected.ciphertextHex, selected.ciphertextHex?.length) ||
              selected.ciphertextHex.length < 188 || selected.ciphertextHex.length > 8192 || selected.ciphertextHex.length % 2) throw Error('Invalid lane grant outbox');
          row.grant = { ciphertextHex: selected.ciphertextHex, rotationSeq: selected.rotationSeq };
        } else if (selected?.status !== 'rejected') throw Error('Explicit decision required');
        row.status = selected.status;
      });
    },
    // Accepted grants survive request expiry, disable and descriptor rotation.
    // Never evict an unacknowledged grant to make room for new requests.
    outbox: () => transaction(state => clone(Object.values(state.rows).filter(row => row.status === 'accepted'))),
    /** Acknowledge only after successful delivery of this exact ciphertext.
     * @param {string} replayKey @param {string} requestId @param {string} ciphertextHex
     */
    acknowledge(replayKey, requestId, ciphertextHex) {
      return transaction(state => {
        const row = state.rows[replayKey];
        if (!hex(replayKey,64) || !row || row.requestId !== requestId || row.status !== 'accepted' ||
            row.grant?.ciphertextHex !== ciphertextHex) throw Error('Outbox acknowledgement mismatch');
        row.status = 'delivered'; delete row.grant;
      });
    },
    close: () => db.close(),
  });
}
