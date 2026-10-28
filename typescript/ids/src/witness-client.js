import { openWitnessPolicyStore } from './indexeddb.js';
import { MAX_WITNESS_ENVELOPE_BYTES } from './witness-policy.js';

/** Bound waits even when an injected transport does not implement cancellation.
 * @template T @param {Promise<T>} pending @param {AbortSignal} signal
 * @returns {Promise<T>} */
function abortable(pending, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(Error('Witness policy download cancelled'));
    if (signal.aborted) { pending.catch(() => {}); abort(); return; }
    signal.addEventListener('abort', abort, { once: true });
    pending.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

/** Browser HTTPS delivery followed by authenticated, durable installation.
 * Configuration must be independently trusted, never derived from a bundle.
 * Opening performs no download or bootstrap. No method falls back to old trust.
 * @param {Parameters<typeof openWitnessPolicyStore>[0] & {
 * url: string, timeoutMs?: number, fetch?: typeof globalThis.fetch
 * }} options
 */
export async function openWitnessPolicyClient(options) {
  const endpoint = new URL(options.url);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.hash || endpoint.search) {
    throw Error('Witness policy endpoint must be an absolute HTTPS URL without credentials, query or fragment');
  }
  const url = endpoint.href;
  const timeoutMs = options.timeoutMs ?? 10000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw Error('Invalid download timeout');
  const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  const store = await openWitnessPolicyStore(options);
  const active = new Set();
  let closed = false;

  /** @param {AbortSignal} signal */
  async function download(signal) {
    /** @type {ReadableStreamDefaultReader<Uint8Array> | undefined} */
    let reader;
    /** @type {Response | undefined} */
    let response;
    try {
      const pending = Promise.resolve(fetcher(url, {
        method: 'GET', redirect: 'error', credentials: 'omit', cache: 'no-store',
        referrerPolicy: 'no-referrer', headers: { Accept: 'application/json' }, signal,
      })).then(result => {
        if (signal.aborted) {
          void result.body?.cancel().catch(() => {});
          throw Error('Witness policy download cancelled');
        }
        return result;
      });
      response = await abortable(pending, signal);
      if (response.status !== 200 || response.redirected || !response.body ||
          !/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get('content-type') ?? '')) {
        throw Error('Invalid witness policy response');
      }
      const declared = response.headers.get('content-length');
      if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_WITNESS_ENVELOPE_BYTES)) {
        throw Error('Oversized witness policy response');
      }
      reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
      let bytes = 0, json = '';
      for (;;) {
        const chunk = await abortable(reader.read(), signal);
        if (chunk.done) break;
        bytes += chunk.value.byteLength;
        if (bytes > MAX_WITNESS_ENVELOPE_BYTES) throw Error('Oversized witness policy response');
        json += decoder.decode(chunk.value, { stream: true });
      }
      json += decoder.decode();
      return json;
    } finally {
      // Never await cancellation: a broken custom stream cannot extend the deadline.
      if (reader) {
        void reader.cancel().catch(() => {});
        reader.releaseLock();
      } else if (response) {
        void response.body?.cancel().catch(() => {});
      }
    }
  }

  /** @param {'bootstrap'|'refresh'} mode @param {{signal?: AbortSignal}} [request] */
  async function install(mode, request = {}) {
    if (closed) throw Error('Witness policy client closed');
    const controller = new AbortController();
    const cancel = () => controller.abort();
    if (request.signal?.aborted) cancel();
    request.signal?.addEventListener('abort', cancel, { once: true });
    active.add(controller);
    const deadline = performance.now() + timeoutMs;
    const timer = setTimeout(cancel, timeoutMs);
    let envelope;
    try {
      controller.signal.throwIfAborted();
      envelope = await download(controller.signal);
      // A blocked event loop can deliver a response before an overdue timer.
      if (performance.now() >= deadline) cancel();
      controller.signal.throwIfAborted();
      if (closed) throw Error('Witness policy client closed');
    } finally {
      clearTimeout(timer);
      active.delete(controller);
      request.signal?.removeEventListener('abort', cancel);
    }
    // Download cancellation ends here. Once the database transaction starts, its
    // normal commit/abort and lost-response reconciliation rules apply.
    return store[mode](envelope);
  }
  return Object.freeze({
    /** Read installed state, not a claim of network freshness. */
    read: () => store.read(),
    /** Independently authorized first installation only. @param {{signal?: AbortSignal}} [request] */
    bootstrap: request => install('bootstrap', request),
    /** Failures reject without clearing history or implicitly bootstrapping. @param {{signal?: AbortSignal}} [request] */
    refresh: request => install('refresh', request),
    close: () => {
      closed = true;
      for (const controller of active) controller.abort();
      store.close();
    },
  });
}
