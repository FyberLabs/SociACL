// Shared strict ASCII grammar: no URL parser, IDNA mapping, or normalization.
/** @param {string} host */
export function publicHost(host) {
  if (host.length > 253 || !host.includes('.') || !host.split('.').every(l => !l.startsWith('xn--') && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return false;
  if (/^[0-9]+$/.test(host.split('.').at(-1) ?? '')) return false;
  return !['localhost','local','internal','home.arpa','test','invalid','example','onion','alt'].some(s => host === s || host.endsWith('.' + s));
}
/** @param {string} s @param {boolean} origin @param {boolean} httpsOnly */
export function webUri(s, origin = false, httpsOnly = true) {
  const m = /^(https?):\/\/([^/:?#]+)(?::([0-9]{1,5}))?(\/[^?#]*)?$/.exec(s);
  if (!m || (httpsOnly && m[1] !== 'https') || !publicHost(m[2])) return false;
  if (m[3] && (+m[3] < 1 || +m[3] > 65535 || String(+m[3]) !== m[3] || m[3] === (m[1] === 'https' ? '443' : '80'))) return false;
  if (origin) return m[4] === undefined;
  if (!m[4] || !/^(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-F]{2})*$/.test(m[4])) return false;
  return m[4].split('/').every(p => { const d = p.replace(/%2E/g,'.'); return d !== '.' && d !== '..'; });
}
