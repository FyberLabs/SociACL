import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
const root = new URL('../../../vectors/ids/', import.meta.url);
const expected = readdirSync(root).filter(f=>f.endsWith('.json')).flatMap(file=>{
  const f=JSON.parse(readFileSync(new URL(file,root),'utf8'));
  return ['accept','reject'].flatMap(d=>f[d].map(c=>`${f.family}/${d}/${c.name}`));
}).sort();
assert.equal(new Set(expected).size,expected.length,'duplicate vector names');
for (const report of process.argv.slice(2)) {
  const names=readFileSync(report,'utf8').trimEnd().split('\n').sort();
  assert.deepEqual(names,expected,report+' must execute every vector exactly once');
}
assert.equal(process.argv.length,4,'pass both Rust and TS reports');
console.log(`${expected.length} shared vectors executed by both languages`);
