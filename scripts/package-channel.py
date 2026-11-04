#!/usr/bin/env python3
"""Prepare read-only package artifacts; publishing runs in a separate job."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

REPO='FyberLabs/SociACL'
PACKAGES={'ids':('typescript/ids','sociacl-ids'),'sociacl':('typescript','sociacl')}
VERSION=re.compile(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)')

def run(*args):
    return subprocess.check_output(args,text=True,stderr=subprocess.PIPE).strip()

def api(path):
    return json.loads(run('gh','api',f'repos/{REPO}/{path}'))

def validate(m,prefix,revision,version):
    package=PACKAGES[prefix][1]
    expected={'schema','repository','channel','revision','version','package','file','sha256','test_run_id'}
    if (not isinstance(m,dict) or set(m)!=expected or m['schema']!=1 or m['repository']!=REPO or m['channel']!='test'
        or m['revision']!=revision or not re.fullmatch('[0-9a-f]{40}',revision) or m['version']!=version or not VERSION.fullmatch(version)
        or m['package']!=package or m['file']!=f'{package}-{version}.tgz' or not re.fullmatch('[0-9a-f]{64}',str(m['sha256']))
        or not re.fullmatch('[1-9][0-9]*',str(m['test_run_id']))):
        raise ValueError('candidate manifest does not identify the exact package revision')
    return m

def verify_run(r,revision):
    if (r.get('head_sha')!=revision or r.get('head_branch')!='master' or r.get('event')!='push' or r.get('conclusion')!='success'
        or r.get('path','').split('@')[0]!='.github/workflows/ci.yml'):
        raise ValueError('candidate lacks successful default-branch CI')

def prepare(prefix,out,env):
    directory,package=PACKAGES[prefix]
    revision,ref=env['GITHUB_SHA'],env['GITHUB_REF']
    if env.get('GITHUB_REPOSITORY')!=REPO or not re.fullmatch('[0-9a-f]{40}',revision):
        raise ValueError('fixed repository and source revision required')
    run('git','merge-base','--is-ancestor',revision,'origin/master')
    if api('branches/master')['protected'] is not True:
        raise ValueError('protected default branch required')
    version=json.loads(Path(directory,'package.json').read_text())['version']
    if not VERSION.fullmatch(version):raise ValueError('stable package version required')
    filename=f'{package}-{version}.tgz'
    out.mkdir(parents=True,exist_ok=True)
    test_tag=f'{prefix}-test-{revision}'
    if ref=='refs/heads/master' and env.get('GITHUB_EVENT_NAME')=='push':
        run('npm','ci','--ignore-scripts','--prefix',directory)
        if prefix=='ids':run('npm','run','build','--prefix',directory)
        run('npm','pack','--ignore-scripts','./'+directory,'--pack-destination',str(out))
        m=dict(schema=1,repository=REPO,channel='test',revision=revision,version=version,package=package,file=filename,
               sha256=hashlib.sha256((out/filename).read_bytes()).hexdigest(),test_run_id=env['GITHUB_RUN_ID'])
        validate(m,prefix,revision,version)
    elif ref==f'refs/tags/{prefix}-v{version}':
        deadline=time.monotonic()+35*60
        while True:
            try:r=api(f'releases/tags/{test_tag}')
            except subprocess.CalledProcessError as error:
                if '(HTTP 404)' not in str(error.stderr):raise
                r=None
            if r:break
            if time.monotonic()>deadline:raise TimeoutError('exact source has no test package')
            time.sleep(15)
        if r['draft'] or not r['prerelease']:raise ValueError('test prerelease required')
        assets={a['name']:a for a in r['assets']}
        if assets.get('release-manifest.json',{}).get('size',16385)>16384:raise ValueError('missing or oversized manifest')
        run('gh','release','download',test_tag,'--repo',REPO,'--pattern','release-manifest.json','--dir',str(out))
        m=validate(json.loads((out/'release-manifest.json').read_text()),prefix,revision,version)
        evidence=api(f'actions/runs/{m["test_run_id"]}')
        while evidence['status']!='completed' and time.monotonic()<deadline:
            time.sleep(15);evidence=api(f'actions/runs/{m["test_run_id"]}')
        verify_run(evidence,revision)
        if filename not in assets or assets[filename]['size']>100*1024*1024:raise ValueError('invalid package asset')
        run('gh','release','download',test_tag,'--repo',REPO,'--pattern',filename,'--dir',str(out))
        if hashlib.sha256((out/filename).read_bytes()).hexdigest()!=m['sha256']:raise ValueError('package digest mismatch')
        bundle='provenance.sigstore.json'
        if bundle not in assets or assets[bundle]['size']>1024*1024:raise ValueError('original provenance bundle required')
        run('gh','release','download',test_tag,'--repo',REPO,'--pattern',bundle,'--dir',str(out))
        proofs=json.loads(run('gh','attestation','verify',str(out/filename),'--bundle',str(out/bundle),'--repo',REPO,
            '--signer-workflow',REPO+'/.github/workflows/ci.yml','--source-ref','refs/heads/master',
            '--source-digest',revision,'--format','json'))
        invocation=re.compile(r'https://github.com/FyberLabs/SociACL/actions/runs/'+re.escape(str(m['test_run_id']))+r'/attempts/[1-9][0-9]*')
        if not any(invocation.fullmatch(str(row.get('verificationResult',{}).get('statement',{}).get('predicate',{}).get('runDetails',{}).get('metadata',{}).get('invocationId',''))) for row in proofs):
            raise ValueError('package was not attested by the successful test run')
        m={**m,'channel':'prod'}
    else:
        raise ValueError('only default-branch pushes or matching stable tags can release')
    (out/'release-manifest.json').write_text(json.dumps(m,sort_keys=True)+'\n')
    (out/(filename+'.sha256')).write_text(m['sha256']+'  '+filename+'\n')

if __name__=='__main__':
    prepare(sys.argv[1],Path(sys.argv[2]).resolve(),os.environ)
