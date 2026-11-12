import { parsePrincipalId } from './ids.js';
import { integer } from './util.js';
const STORE = 'descriptor-floor';
/** @typedef {{revision:number,digest:string}} Floor */
/** @param {Floor} floor */
function valid(floor) {
  return floor && integer(floor.revision) && floor.revision > 0 && typeof floor.digest === 'string' &&
    floor.digest.length === 64 && /^[0-9a-f]{64}$/.test(floor.digest);
}
/** Durable observation floor, not freshness or discovery authority. Bootstrap needs
 * an independently authenticated exact descriptor anchor. Missing state on reopen
 * fails, never silently repeats first use. Origin storage and caller are trusted.
 * @param {{name:string,owner:string,anchor:Floor,now:()=>number,create?:boolean,indexedDB?:IDBFactory}} options
 */
export async function openFirstContactFloor(options) {
  const {name,owner,now,create=false}=options, anchor=structuredClone(options.anchor);
  if(typeof name!=='string' || !name || !parsePrincipalId(owner).ok || !valid(anchor) || typeof now!=='function')
    throw Error('Invalid descriptor floor configuration');
  const factory=options.indexedDB ?? globalThis.indexedDB;
  if(!factory)throw Error('IndexedDB unavailable');
  /** @type {IDBDatabase} */
  const db=await new Promise((resolve,reject)=>{
    const request=factory.open(name,1);let abandoned=false;
    request.onupgradeneeded=()=>{if(!create){request.transaction?.abort();return;}request.result.createObjectStore(STORE);};
    request.onblocked=()=>{abandoned=true;reject(Error('Descriptor floor database blocked'));};
    request.onerror=()=>reject(request.error ?? Error('Descriptor floor unavailable'));
    request.onsuccess=()=>{if(abandoned)request.result.close();else resolve(request.result);};
  });
  db.onversionchange=()=>db.close();
  function time(){const t=now();if(!integer(t))throw Error('Invalid clock');return t;}
  /** @param {(now:number)=>void} verify @param {number} t */
  function authenticated(verify,t){if(verify(t)!==undefined)throw Error('Synchronous descriptor verification required');}
  /** @param {Floor|undefined} candidate @param {(now:number)=>void} verify @param {boolean} [initialize] @returns {Promise<Floor>} */
  function transaction(candidate,verify,initialize=false){
    return new Promise((resolve,reject)=>{
      const tx=db.transaction(STORE,'readwrite',{durability:'strict'});
      /** @type {unknown} */let failure;
      /** @type {Floor} */let result;
      let committedAt=0;
      tx.onabort=()=>reject(failure ?? tx.error ?? Error('Descriptor floor aborted'));
      tx.onerror=()=>{};
      tx.oncomplete=()=>{try{const t=time();if(t<committedAt)throw Error('Clock rollback');authenticated(verify,t);resolve(result);}catch(e){reject(e);}};
      if(tx.durability!=='strict'){failure=Error('Strict durability unavailable');tx.abort();return;}
      const store=tx.objectStore(STORE),get=store.get(owner);
      get.onsuccess=()=>{try{
        const t=time();let saved=get.result;
        if(!saved){if(!initialize)throw Error('Missing descriptor continuity');saved={v:1,owner,...anchor,clock:t};}
        if(saved.v!==1 || saved.owner!==owner || !valid(saved) || !integer(saved.clock) || saved.clock>t ||
          saved.revision<anchor.revision || (saved.revision===anchor.revision && saved.digest!==anchor.digest))throw Error('Invalid descriptor continuity');
        authenticated(verify,t);
        if(candidate){
          if(!valid(candidate) || candidate.revision<saved.revision ||
            (candidate.revision===saved.revision && candidate.digest!==saved.digest))throw Error('Descriptor rollback or equivocation');
          saved={v:1,owner,...candidate,clock:t};
        }else saved.clock=t;
        committedAt=t;result=Object.freeze({revision:saved.revision,digest:saved.digest});store.put(saved,owner);
      }catch(e){failure=e;tx.abort();}};
    });
  }
  try{await transaction(undefined,()=>{},create);}catch(e){db.close();throw e;}
  return Object.freeze({owner,
    read:()=>transaction(undefined,()=>{}),
    /** Caller must authenticate this exact candidate synchronously inside the
     * transaction. No plaintext or network work belongs in this callback.
     * @param {Floor} candidate @param {(now:number)=>void} verify */
    observe:(candidate,verify)=>{
      if(typeof verify!=='function')return Promise.reject(Error('Descriptor verifier required'));
      const copy=structuredClone(candidate);
      return transaction({revision:copy.revision,digest:copy.digest},verify);
    },
    close:()=>db.close(),
  });
}
