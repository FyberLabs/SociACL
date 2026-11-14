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

deletion=f['deletion'];expected={**deletion['claims'],'ownerPub':f['owner']}
assert pair('sociacl_verify_private_deletion',deletion['proof'],expected,1000)==1
assert pair('sociacl_verify_private_deletion',deletion['proof'],expected,61000)==0
assert pair('sociacl_verify_private_deletion',deletion['proof'],expected,999)==0
for field,value in [('tenant','22222222-2222-4222-8222-222222222222'),('object',f['object']+'x'),
                    ('owner','other'),('ownerPub','other'),('objectVersion',4),('fence','b'*64),('issuedAt',1001),('expiresAt',60000)]:
    assert pair('sociacl_verify_private_deletion',deletion['proof'],{**expected,field:value},2000)==0,field
assert pair('sociacl_verify_private_deletion',f['cancel']['proof'],expected,2000)==0
print('Browser deletion command matches native exact-scope verification; unshare refuses')

# Group snapshots bind separate member and object-set HAM state. A valid
# signature cannot conceal subsequent withdrawal or a newer object-set edge.
g=f['groupEpoch'];m=g['manifest']
expected={'ownerPub':f['owner'],'object':f['object'],'epoch':1,'revisionId':m['revisionId']}
assert pair('sociacl_verify_epoch_manifest',g,expected)==1
for field in ['hamState','stated']:
    changed=json.loads(json.dumps(g));changed['snapshot']['objectSet'][field]=0
    assert pair('sociacl_verify_epoch_manifest',changed,expected)==0
history={'object':f['object'],'manifests':[{'document':g,'expected':expected}],
    'finalizations':[{'proof':f['groupFinalization'],'ownerPub':f['owner'],'seenAt':1000}],
    'current':g['snapshot'],'nowMs':3601000,'groupWindowMs':3600000,
    'anchorFinalizationId':f['groupFinalization']['finalizationId'],
    'minimumEpoch':1,'expectedEpoch':1,'expectedRevisionId':m['revisionId']}
raw=json.dumps(history).encode();assert fn(raw,len(raw))==1
# The trusted consumer must independently resolve the group settlement policy.
missing=json.loads(json.dumps(history));missing.pop('groupWindowMs')
raw=json.dumps(missing).encode();assert fn(raw,len(raw))==0
for part in ['member','edge']:
    changed=json.loads(json.dumps(history))
    row=next(e for e in changed['current']['entries'] if e['scope']!='direct') if part=='member' else changed['current']['objectSet']
    row['stated']=0;row['hamState']+=1
    raw=json.dumps(changed).encode();assert fn(raw,len(raw))==0
print('Browser group epoch binds native member withdrawal and independent object-set cancellation')
