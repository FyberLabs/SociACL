import { advanceWitnessPolicy, verifyWitnessPolicyEnvelope } from './witness-policy.js';
import { advanceWitnessCheckpoint, verifyWitnessCheckpoint } from './witness-checkpoint.js';
import { parsePrincipalId } from './ids.js';
import { integer, utf8, b64 } from './util.js';

const STORE = 'witness-policy', KEY = 'installed';
const LEGACY = 'sociacl-witness-policy-installed-v1';
const RECORD = 'sociacl-witness-checkpoint-installed-v1';
/** @typedef {Readonly<{challenge:string, client:string, audience:string, rootEpoch:number, operation:'refresh'}>} Request */
/** @typedef {{request:Request, generation:number, wall:number, mono:number}} Pending */
/** @typedef {{checkpoint:string, policy:string, deadline:number, expiresAt:number, generation:number}} Lease */
/** Refresh existing browser policy continuity using authenticated complete checkpoints.
 * No bootstrap, recovery or root migration. Config and origin storage are trusted.
 * Reopening requires a new checkpoint; a saved row is historical evidence only.
 * @param {Omit<import('./types.js').WitnessCheckpointExpectations,'now'|'challenge'> & {
 * name:string, now:()=>number, monotonic?:()=>number, indexedDB?:IDBFactory,
 * crypto?:Pick<Crypto,'getRandomValues'>}} options
 */
export async function openWitnessCheckpointStore(options) {
  const { name, managementRoot, root, rootEpoch, audience, client, minimumRevision, now } = options;
  const monotonic = options.monotonic ?? (() => performance.now());
  const rng = options.crypto ?? globalThis.crypto;
  const factory = options.indexedDB ?? globalThis.indexedDB;
  if (typeof name !== 'string' || !name || !parsePrincipalId(managementRoot).ok ||
      !parsePrincipalId(root).ok || managementRoot === root || !integer(rootEpoch) || rootEpoch < 1 ||
      !integer(minimumRevision) || minimumRevision < 1 || typeof now !== 'function' || typeof monotonic !== 'function' ||
      [audience,client].some(x => typeof x !== 'string' || !x || x.length > 1024 || utf8.encode(x).length > 1024) ||
      !rng || typeof rng.getRandomValues !== 'function' || !factory) throw Error('Invalid checkpoint store configuration');
  let closed = false, generation = 0;
  /** @type {Pending|undefined} */ let pending;
  /** @type {Lease|undefined} */ let lease;
  /** @type {number|undefined} */ let lastWall;
  /** @type {number|undefined} */ let lastMono;
  function invalidate() { generation++; pending = undefined; lease = undefined; }
  function clock() {
    const wall = now(), mono = monotonic();
    if (closed || !integer(wall) || !Number.isFinite(mono) || mono < 0 ||
        (lastWall !== undefined && wall < lastWall) || (lastMono !== undefined && mono < lastMono)) {
      invalidate(); throw Error('Untrusted or backward checkpoint clock');
    }
    lastWall = wall; lastMono = mono;
    return { wall, mono };
  }
  clock();
  const db = await new Promise((resolve, reject) => {
    const request = factory.open(name, 2);
    let abandoned = false;
    request.onupgradeneeded = event => {
      if (event.oldVersion === 0) request.result.createObjectStore(STORE);
      else if (!request.result.objectStoreNames.contains(STORE)) request.transaction?.abort();
    };
    request.onerror = () => reject(request.error ?? Error('Checkpoint database open failed'));
    request.onblocked = () => { abandoned = true; reject(Error('Checkpoint database upgrade blocked')); };
    request.onsuccess = () => {
      if (abandoned) request.result.close();
      else resolve(request.result);
    };
  });
  db.onversionchange = () => { closed = true; invalidate(); db.close(); };
  /** @param {string} challenge @param {number} time @param {number} [floor] */
  const expectations = (challenge, time, floor = minimumRevision) =>
    ({ managementRoot, root, rootEpoch, audience, client, challenge, minimumRevision:floor, now:time });
  /** @param {any} record */
  function saved(record) {
    if (!record || typeof record !== 'object' || typeof record.state !== 'string' || !integer(record.acceptedAt))
      throw Error('Missing or corrupt checkpoint continuity');
    if (record.type === LEGACY && Object.keys(record).length === 4 && typeof record.envelope === 'string') {
      const result = advanceWitnessPolicy(record.envelope, record.state, root, audience, 1, record.acceptedAt);
      if (!result.ok || result.value.revision !== JSON.parse(record.state).revision) throw Error('Invalid prior policy');
      return result.value;
    }
    if (record.type !== RECORD || Object.keys(record).length !== 6 || typeof record.challenge !== 'string' ||
        typeof record.checkpoint !== 'string' || typeof record.policy !== 'string') throw Error('Invalid checkpoint row');
    const result = verifyWitnessCheckpoint(record.checkpoint, record.policy, expectations(record.challenge, record.acceptedAt, 1));
    if (!result.ok || JSON.stringify(result.value.state) !== record.state) throw Error('Invalid saved checkpoint');
    return result.value.state;
  }
  function readRow() {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const request = tx.objectStore(STORE).get(KEY);
      tx.oncomplete = () => resolve(request.result);
      tx.onabort = () => reject(tx.error ?? Error('Checkpoint read failed'));
    });
  }
  /** @param {Pending} active @param {string} checkpoint @param {string} policy */
  function check(active, checkpoint, policy) {
    const time = clock();
    if (active.generation !== generation) throw Error('Checkpoint request superseded');
    const verified = verifyWitnessCheckpoint(checkpoint, policy, expectations(active.request.challenge, time.wall));
    if (!verified.ok) throw Error('Invalid checkpoint response');
    // Anchor to request time, never to response or read time. A stalled UTC
    // clock cannot extend the lease; requests themselves also live at most 300s.
    const signedPolicy = verifyWitnessPolicyEnvelope(policy, root, audience, time.wall);
    if (!signedPolicy.ok) throw Error('Invalid policy response');
    const expiresAt = Math.min(verified.value.expiresAt, signedPolicy.value.expiresAt);
    const deadline = active.mono + Math.min(300, expiresAt - active.wall) * 1000;
    if (time.mono >= deadline) throw Error('Checkpoint monotonic lease expired');
    return { verified:verified.value, time, deadline, expiresAt };
  }
  async function beginRefresh() {
    invalidate();
    const op = generation, time = clock();
    try {
      saved(await readRow()); // Missing or corrupt state is never initial enrollment.
      const current = clock();
      if (generation !== op || current.mono - time.mono >= 300000) throw Error('Checkpoint request superseded or expired');
      const request = Object.freeze({ challenge:b64(rng.getRandomValues(new Uint8Array(32))), client, audience, rootEpoch,
        operation:/** @type {const} */('refresh') });
      pending = { request, generation:op, ...time };
      return request;
    } catch (error) { if (generation === op) invalidate(); throw error; }
  }
  /** Consume this instance's current request once. A failed attempt requires a new request.
   * @param {Request} request @param {string} checkpoint @param {string} policy */
  async function install(request, checkpoint, policy) {
    const active = pending;
    if (!active || active.request !== request || active.generation !== generation || closed) throw Error('Unknown or consumed checkpoint request');
    pending = undefined;
    try {
      // Verification happens again under the write lock, never just before waiting.
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite', { durability:'strict' });
        if (tx.durability !== 'strict') { tx.abort(); reject(Error('Strict durability unavailable')); return; }
        /** @type {unknown} */ let failure;
        /** @param {unknown} error */
        const abort = error => { failure = error; tx.abort(); };
        tx.onabort = () => reject(failure ?? tx.error ?? Error('Checkpoint transaction aborted'));
        tx.oncomplete = () => resolve(undefined);
        const objectStore = tx.objectStore(STORE);
        const get = objectStore.get(KEY);
        get.onsuccess = () => {
          try {
            const previous = saved(get.result);
            const { time } = check(active, checkpoint, policy);
            const candidate = advanceWitnessCheckpoint(checkpoint, policy, JSON.stringify(previous), expectations(request.challenge, time.wall));
            if (!candidate.ok) throw Error('Checkpoint violates local continuity');
            const put = objectStore.put({ type:RECORD, checkpoint, policy, challenge:request.challenge,
              acceptedAt:time.wall, state:JSON.stringify(candidate.value.state) }, KEY);
            put.onsuccess = () => { try { check(active, checkpoint, policy); } catch (error) { abort(error); } };
          } catch (error) { abort(error); }
        };
      });
      const { verified, deadline, expiresAt } = check(active, checkpoint, policy);
      lease = { checkpoint, policy, deadline, expiresAt, generation:active.generation };
      return verified.state;
    } catch (error) { if (generation === active.generation) invalidate(); throw error; }
  }
  async function readInstalled() {
    if (closed) throw Error('Checkpoint store closed');
    try {
      const state = saved(await readRow());
      if (closed) throw Error('Checkpoint store closed');
      if (state.revision < minimumRevision) throw Error('Installed checkpoint below floor');
      return state;
    } catch (error) { invalidate(); throw error; }
  }
  async function readFresh() {
    const active = lease;
    if (!active) throw Error('Fresh checkpoint required');
    try {
      const row = await readRow();
      const state = saved(row), time = clock();
      if (lease !== active || generation !== active.generation || row.type !== RECORD ||
          row.checkpoint !== active.checkpoint || row.policy !== active.policy || state.revision < minimumRevision ||
          time.wall >= active.expiresAt || time.mono >= active.deadline) throw Error('Fresh checkpoint required');
      return state;
    } catch (error) { if (lease === active) invalidate(); throw error; }
  }
  return Object.freeze({ beginRefresh, install, readInstalled, readFresh,
    cancel: () => invalidate(),
    close: () => { closed = true; invalidate(); db.close(); },
  });
}
