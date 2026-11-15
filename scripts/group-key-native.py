"""CI-only group browser producer compatibility against the actual C exports."""
import ctypes
import json
import os
from pathlib import Path
if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Native contracts run only in CI')
f=json.loads(Path('target/ids/group-key.json').read_text())
lib=ctypes.CDLL(str(Path('target/debug/libsociacl.so').resolve()))
m=f['epoch']['manifest']
e={'object':m['object'],'ownerPub':f['owner'],'epoch':m['epoch'],'revisionId':m['revisionId']}
pair=lib.sociacl_verify_group_epoch_manifest
pair.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_char_p,ctypes.c_size_t];pair.restype=ctypes.c_int
p=json.dumps(f['epoch']).encode();expected=json.dumps(e).encode()
assert pair(p,len(p),expected,len(expected))==1
history={'object':m['object'],'current':f['epoch']['snapshot'],'config':f['config'],
 'manifests':[{'document':f['epoch'],'expected':e}],
 'finalizations':[{'proof':f['finalization'],'ownerPub':f['owner'],'seenAt':100}],
 'nowMs':3600100,'anchorFinalizationId':f['finalization']['finalizationId'],'minimumEpoch':1,
 'expectedEpoch':1,'expectedRevisionId':m['revisionId']}
selected=lib.sociacl_match_settled_group_epoch;selected.argtypes=[ctypes.c_char_p,ctypes.c_size_t];selected.restype=ctypes.c_int
def call(value):
    raw=json.dumps(value).encode();return selected(raw,len(raw))
assert call(history)==1
history['nowMs']-=1;assert call(history)==0
history['nowMs']+=1;history['current']['members'][0]['stated']=0;assert call(history)==0
history['current']['members'][0]['stated']=1;history['current']['ownerIdentityHead']=1;assert call(history)==0
print('Browser independent group snapshot, manifest and finalization match native selection')
