import { openWitnessCheckpointStore } from './checkpoint-store.js';
import { uniqueJson } from './json.js';

// Includes JSON string escaping around the two signed envelopes. Inner format
// limits remain independently enforced by the checkpoint store.
export const MAX_CHECKPOINT_RESPONSE_BYTES = 4194304;
/** @template T @param {Promise<T>} pending @param {AbortSignal} signal
 * @returns {Promise<T>} */
function abortable(pending, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(Error('Checkpoint refresh cancelled'));
    if (signal.aborted) { pending.catch(() => {}); abort(); return; }
    signal.addEventListener('abort', abort, { once:true });
    pending.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}
/** Authenticated HTTPS refresh of existing checkpoint continuity.
 * getAccessToken must use the deployment's independently authenticated management
 * enrollment; an ordinary account token is not recovery authorization.
 * Opening never downloads or bootstraps. All refresh failures block fresh reads.
 * @param {Parameters<typeof openWitnessCheckpointStore>[0] & {
 * url:string, getAccessToken:(signal:AbortSignal)=>Promise<string>,
 * timeoutMs?:number, fetch?:typeof globalThis.fetch }} options
 */
export async function openWitnessCheckpointClient(options) {
  const endpoint = new URL(options.url);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash)
    throw Error('Checkpoint endpoint must be HTTPS without credentials, query or fragment');
  const url = endpoint.href, timeoutMs = options.timeoutMs ?? 10000;
  const getAccessToken = options.getAccessToken;
  if (typeof getAccessToken !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000)
    throw Error('Invalid checkpoint client configuration');
  const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  const store = await openWitnessCheckpointStore(options);
  /** @type {AbortController|undefined} */ let active;
  let closed = false;
  /** @param {string} body @param {string} token @param {AbortSignal} signal */
  async function download(body, token, signal) {
    /** @type {ReadableStreamDefaultReader<Uint8Array>|undefined} */ let reader;
    /** @type {Response|undefined} */ let response;
    try {
      const pending = Promise.resolve(fetcher(url, {
        method:'POST', body, redirect:'error', credentials:'omit', cache:'no-store',
        referrerPolicy:'no-referrer', signal,
        headers:{Accept:'application/json', 'Content-Type':'application/json', Authorization:`Bearer ${token}`},
      })).then(result => {
        if (signal.aborted) { void result.body?.cancel().catch(() => {}); throw Error('Checkpoint refresh cancelled'); }
        return result;
      });
      response = await abortable(pending, signal);
      if (response.status !== 200 || response.redirected || !response.body ||
          !/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get('content-type') ?? ''))
        throw Error('Invalid checkpoint HTTP response');
      const length = response.headers.get('content-length');
      if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_CHECKPOINT_RESPONSE_BYTES))
        throw Error('Oversized checkpoint response');
      reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8', {fatal:true, ignoreBOM:true});
      let bytes = 0, json = '';
      for (;;) {
        const chunk = await abortable(reader.read(), signal);
        if (chunk.done) break;
        bytes += chunk.value.byteLength;
        if (bytes > MAX_CHECKPOINT_RESPONSE_BYTES) throw Error('Oversized checkpoint response');
        json += decoder.decode(chunk.value, {stream:true});
      }
      json += decoder.decode();
      const doc = /** @type {Record<string,unknown>|null} */(uniqueJson(json));
      if (!doc || typeof doc !== 'object' || Array.isArray(doc) || Object.keys(doc).length !== 3 ||
          doc.type !== 'sociacl-witness-checkpoint-response-v1' || typeof doc.checkpoint !== 'string' || typeof doc.policy !== 'string')
        throw Error('Invalid checkpoint response schema');
      return {checkpoint:doc.checkpoint, policy:doc.policy};
    } finally {
      if (reader) { void reader.cancel().catch(() => {}); reader.releaseLock(); }
      else if (response) void response.body?.cancel().catch(() => {});
    }
  }
  /** A new call supersedes the previous call; no automatic retry or stale fallback.
   * Timeout covers credentials, download and commit/return, not only HTTP.
   * @param {{signal?:AbortSignal}} [request] */
  async function refresh(request = {}) {
    if (closed) throw Error('Checkpoint client closed');
    active?.abort();
    store.cancel();
    const controller = new AbortController();
    active = controller;
    const cancel = () => controller.abort();
    const invalidate = () => { if (active === controller) store.cancel(); };
    controller.signal.addEventListener('abort', invalidate, {once:true});
    request.signal?.addEventListener('abort', cancel, {once:true});
    if (request.signal?.aborted) cancel();
    const deadline = performance.now() + timeoutMs;
    const timer = setTimeout(cancel, timeoutMs);
    function check() {
      if (performance.now() >= deadline || closed || active !== controller) cancel();
      controller.signal.throwIfAborted();
    }
    try {
      check();
      const ticket = await abortable(store.beginRefresh(), controller.signal);
      check();
      const token = await abortable(Promise.resolve(getAccessToken(controller.signal)), controller.signal);
      check();
      // OAuth bearer token syntax; reject whitespace/header injection and bound it.
      if (typeof token !== 'string' || token.length > 8192 || !/^[A-Za-z0-9._~+/-]+=*$/.test(token))
        throw Error('Invalid management credential');
      const body = JSON.stringify({type:'sociacl-witness-checkpoint-request-v1', ...ticket});
      const reply = await download(body, token, controller.signal);
      check();
      await abortable(store.install(ticket, reply.checkpoint, reply.policy), controller.signal);
      check();
      const state = await abortable(store.readFresh(), controller.signal);
      check();
      return state;
    } catch {
      // Do not expose provider exceptions that may contain credential material.
      if (active === controller) store.cancel();
      throw Error('Checkpoint refresh failed');
    } finally {
      clearTimeout(timer);
      request.signal?.removeEventListener('abort', cancel);
      controller.signal.removeEventListener('abort', invalidate);
      if (active === controller) active = undefined;
    }
  }
  return Object.freeze({refresh, readFresh:()=>store.readFresh(), readInstalled:()=>store.readInstalled(),
    cancel:()=>{active?.abort(); store.cancel();},
    close:()=>{closed=true; active?.abort(); store.close();},
  });
}
