// Read-only inventory of exported IDs; rejected IDs are never repaired.
import { createInterface } from 'node:readline';
import { parseObjectId } from '../src/index.js';
let total=0, accepted=0, rejected=0;
for await (const line of createInterface({input:process.stdin,crlfDelay:Infinity})) {
  if (!line.trim()) continue;
  total++;
  let value; try {value=JSON.parse(line);} catch {rejected++;console.log(JSON.stringify({line:total,reason:'invalid-json'}));continue;}
  const id=typeof value==='string'?value:value?.id;
  const result=parseObjectId(id);
  if(result.ok) accepted++;
  else {rejected++;console.log(JSON.stringify({line:total,id,reason:result.reason}));}
}
console.error(JSON.stringify({total,accepted,rejected}));
if(rejected) process.exitCode=1;
