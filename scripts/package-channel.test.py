import importlib.util
from pathlib import Path
import unittest
import json
import hashlib
import tempfile
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('channel',Path(__file__).with_name('package-channel.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class PackageChannelTests(unittest.TestCase):
    def test_exact_package_version_revision_and_digest(self):
        m=dict(schema=1,repository=p.REPO,channel='test',revision='a'*40,version='0.10.0',package='sociacl-ids',file='sociacl-ids-0.10.0.tgz',sha256='b'*64,test_run_id='1')
        self.assertEqual(p.validate(m,'ids','a'*40,'0.10.0'),m)
        for key,value in [('package','sociacl'),('file','../secret'),('channel','prod'),('revision','c'*40),('version','0.10.1'),('sha256','latest'),('test_run_id','0'),('extra',1)]:
            with self.subTest(key=key),self.assertRaises(ValueError):p.validate(dict(m,**{key:value}),'ids','a'*40,'0.10.0')
    def test_only_successful_exact_main_run_can_promote(self):
        r=dict(head_sha='a'*40,head_branch='master',event='push',conclusion='success',path='.github/workflows/ci.yml')
        p.verify_run(r,'a'*40)
        for key,value in [('head_sha','b'*40),('head_branch','feature'),('event','pull_request'),('conclusion','failure'),('path','other.yml')]:
            with self.subTest(key=key),self.assertRaises(ValueError):p.verify_run(dict(r,**{key:value}),'a'*40)
    def test_stable_tag_copies_exact_test_bytes_without_running_npm(self):
        revision='a'*40; payload=b'original tested tarball bytes'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);package=root/'package';package.mkdir()
            (package/'package.json').write_text('{"version":"0.10.0"}')
            out=root/'output';filename='sociacl-ids-0.10.0.tgz'
            manifest=dict(schema=1,repository=p.REPO,channel='test',revision=revision,version='0.10.0',package='sociacl-ids',file=filename,sha256=hashlib.sha256(payload).hexdigest(),test_run_id='123')
            calls=[]
            def run(*args):
                calls.append(args)
                if args[0]=='git':return ''
                if args[:3]==('gh','attestation','verify'):
                    self.assertIn('--bundle',args)
                    self.assertEqual(args[args.index('--bundle')+1],str(out/'provenance.sigstore.json'))
                    return json.dumps([dict(verificationResult=dict(statement=dict(predicate=dict(runDetails=dict(metadata=dict(invocationId='https://github.com/FyberLabs/SociACL/actions/runs/123/attempts/1'))))))])
                self.assertEqual(args[:3],('gh','release','download'))
                name=args[args.index('--pattern')+1]
                (out/name).write_bytes(json.dumps(manifest).encode() if name=='release-manifest.json' else payload)
                return ''
            release=dict(draft=False,prerelease=True,assets=[dict(name='release-manifest.json',size=500),dict(name=filename,size=len(payload)),dict(name='provenance.sigstore.json',size=500)])
            evidence=dict(head_sha=revision,head_branch='master',event='push',conclusion='success',status='completed',path='.github/workflows/ci.yml')
            env=dict(GITHUB_REPOSITORY=p.REPO,GITHUB_SHA=revision,GITHUB_REF='refs/tags/ids-v0.10.0',GITHUB_EVENT_NAME='push')
            with patch.dict(p.PACKAGES,ids=(str(package),'sociacl-ids')),patch.object(p,'run',side_effect=run),patch.object(p,'api',side_effect=[dict(protected=True),release,evidence]):
                p.prepare('ids',out,env)
            self.assertEqual((out/filename).read_bytes(),payload)
            self.assertEqual(json.loads((out/'release-manifest.json').read_text())['channel'],'prod')
            self.assertFalse(any(c[0]=='npm' for c in calls))
if __name__=='__main__':unittest.main()
