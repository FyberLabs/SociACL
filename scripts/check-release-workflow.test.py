"""Regressions for mutable actions and stranded tag/pack jobs."""
import copy
import importlib.util
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('workflow_check', ROOT/'scripts/check-release-workflow.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class WorkflowContract(unittest.TestCase):
    def setUp(self):
        self.document = yaml.safe_load((ROOT/'.github/workflows/ci.yml').read_text())

    def test_current_workflow_and_publication_serialization(self):
        check.check(self.document)
        for name in ('release-ids', 'release-sociacl'):
            self.assertIn('concurrency', self.document['jobs'][name])

    def test_each_tag_or_pack_concurrency_is_rejected_even_without_cancellation(self):
        for name in check.PREPARATION_JOBS:
            document = copy.deepcopy(self.document)
            document['jobs'][name]['concurrency'] = {'group':'shared', 'cancel-in-progress':False}
            with self.subTest(job=name), self.assertRaises(ValueError):
                check.check(document)

    def test_workflow_concurrency_is_rejected(self):
        self.document['concurrency'] = 'shared'
        with self.assertRaises(ValueError): check.check(self.document)

    def test_missing_preparation_job_is_rejected(self):
        del self.document['jobs']['pack-ids']
        with self.assertRaises(ValueError): check.check(self.document)

    def test_floating_action_and_reusable_workflow_are_rejected(self):
        for job in ({'steps':[{'uses':'actions/checkout@v7'}]},
                    {'uses':'org/repo/.github/workflows/build.yml@main'},
                    {'steps':[{'uses':'docker://alpine:latest'}]}):
            self.document['jobs']['new-job'] = job
            with self.subTest(job=job), self.assertRaises(ValueError): check.check(self.document)

    def test_explicit_rust_versions_are_preserved(self):
        for name in ('msrv','test'):
            document = copy.deepcopy(self.document)
            for step in document['jobs'][name]['steps']:
                if step.get('uses','').startswith('dtolnay/rust-toolchain@'):
                    step['with'].pop('toolchain')
            with self.subTest(job=name), self.assertRaises(ValueError): check.check(document)

    def test_local_actions_and_digest_pinned_images_are_allowed(self):
        self.document['jobs']['new-job'] = {'steps':[{'uses':'./.github/actions/local'},
            {'uses':'docker://alpine@sha256:'+'a'*64}]}
        check.check(self.document)


if __name__ == '__main__': unittest.main()
