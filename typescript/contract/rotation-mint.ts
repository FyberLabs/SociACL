/** Portable rotation material. The entropy callback must fill the supplied buffer
 * from a cryptographically secure source; callers retain no buffer ownership. */
import {p256} from '@noble/curves/nist.js';
import {b64,hex} from '../ids/src/util.js';
import type {RotationMint} from './keyring-rotation.ts';

export function mintRotationMaterial(fill:(bytes:Uint8Array)=>void=(bytes)=>{crypto.getRandomValues(bytes);}):RotationMint {
  const owned:Uint8Array[]=[];
  const draw=()=>{const bytes=new Uint8Array(32);owned.push(bytes);fill(bytes);return bytes;};
  const scalar=()=>{
    // Bound refusal if a broken entropy source repeatedly supplies invalid scalars.
    for(let attempt=0;attempt<128;attempt++){
      const bytes=draw();
      if(p256.utils.isValidSecretKey(bytes))return bytes;
      bytes.fill(0);
    }
    throw Error('rotation-entropy');
  };
  const point=(secret:Uint8Array)=>{const raw=p256.getPublicKey(secret,false);return `${b64(raw.subarray(1,33))}.${b64(raw.subarray(33))}`;};
  try{
    const signing=scalar(),encryption=scalar(),lane=draw(),contact=draw();
    if(hex(contact)===hex(lane))contact[0]^=1;
    return {signingPub:point(signing),signingPriv:b64(signing),epub:point(encryption),epriv:b64(encryption),
      laneId:hex(lane),contactLaneSecret:hex(contact)};
  }finally{for(const bytes of owned)bytes.fill(0);}
}
