// JWS JSON must not contain duplicate object members. JSON.parse alone loses them.
/** @param {string} source @returns {unknown} */
export function uniqueJson(source) {
  let at = 0;
  const ws = () => { while (/[ \t\r\n]/.test(source[at] ?? '') && at < source.length) at++; };
  const string = () => {
    const start = at++;
    while (at < source.length) {
      const c = source[at++];
      if (c === '\\') at++;
      else if (c === '"') return /** @type {string} */ (JSON.parse(source.slice(start, at)));
    }
    throw Error('unterminated JSON string');
  };
  /** @param {number} depth */
  const value = (depth) => {
    if (depth > 16) throw Error('JSON depth');
    ws();
    const c = source[at];
    if (c === '"') { string(); return; }
    if (c === '{' || c === '[') {
      at++; ws(); const end = c === '{' ? '}' : ']'; const keys = new Set();
      if (source[at] === end) { at++; return; }
      while (at < source.length) {
        if (c === '{') {
          ws(); if (source[at] !== '"') throw Error('JSON key');
          const key = string(); if (keys.has(key)) throw Error('duplicate member'); keys.add(key);
          ws(); if (source[at++] !== ':') throw Error('JSON colon');
        }
        value(depth + 1); ws();
        if (source[at] === end) { at++; return; }
        if (source[at++] !== ',') throw Error('JSON comma');
      }
      throw Error('JSON end');
    }
    const m = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(source.slice(at));
    if (!m) throw Error('JSON token'); at += m[0].length;
  };
  value(0); ws(); if (at !== source.length) throw Error('JSON trailing data');
  return JSON.parse(source);
}
