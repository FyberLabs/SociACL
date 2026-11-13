"""CI-only consumer producer contracts against the actual native verifier."""
import ctypes
import json
import os
from pathlib import Path
if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Native contracts run only in CI')
f=json.loads(Path('target/ids/private-media.json').read_text())
lib=ctypes.CDLL(str(Path('target/debug/libsociacl.so').resolve()))
def pair(name, proof, expected, *extra):
    fn=getattr(lib,name)
    fn.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_char_p,ctypes.c_size_t]+[ctypes.c_uint64]*len(extra)
    fn.restype=ctypes.c_int
    p=json.dumps(proof).encode();e=json.dumps(expected).encode()
    return fn(p,len(p),e,len(e),*extra)
for grant in [f['grant'],f['cancel']]:
    expected={**grant['claims'],'ownerPub':f['owner']}
    assert pair('sociacl_verify_private_grant',grant['proof'],expected)==1
    assert pair('sociacl_verify_private_grant',grant['proof'],{**expected,'epoch':2})==0
m=f['epoch']['manifest']
expected={'ownerPub':f['owner'],'object':f['object'],'epoch':1,'revisionId':m['revisionId']}
assert pair('sociacl_verify_epoch_manifest',f['epoch'],expected)==1
assert pair('sociacl_verify_epoch_manifest',f['epoch'],{**expected,'revisionId':'f'*64})==0
s=f['status'];expected={k:s[k] for k in ['object','epoch','revisionId','accessor','grantRevision','stated','zookie']}
expected['ownerPub']=f['owner']
assert pair('sociacl_verify_epoch_status',s,expected,s['signedAt'],0,60000)==1
assert pair('sociacl_verify_epoch_status',s,expected,s['signedAt']+60001,0,60000)==0
history={'object':f['object'],'manifests':[{'document':f['epoch'],'expected':{'ownerPub':f['owner'],'object':f['object'],'epoch':1,'revisionId':m['revisionId']}}],
    'finalizations':[{'proof':f['finalization'],'ownerPub':f['owner'],'seenAt':1000}],
    'current':f['epoch']['snapshot'],'nowMs':3601000,'anchorFinalizationId':f['finalization']['finalizationId'],
    'minimumEpoch':1,'expectedEpoch':1,'expectedRevisionId':m['revisionId']}
fn=lib.sociacl_match_settled_epoch;fn.argtypes=[ctypes.c_char_p,ctypes.c_size_t];fn.restype=ctypes.c_int
raw=json.dumps(history).encode();assert fn(raw,len(raw))==1
history['finalizations'][0]['proof']['signature']='0'*128
raw=json.dumps(history).encode();assert fn(raw,len(raw))==0
print('Browser grants, cancellation, manifest, finalization and status match native verification')
