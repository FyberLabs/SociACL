"""Read-only checks for immutable actions and non-cancelling pack preparation."""
from pathlib import Path
import re
import sys

import yaml

PREPARATION_JOBS = {'tag-ids', 'tag-sociacl', 'pack-ids', 'pack-sociacl'}


def check(document):
    if not isinstance(document, dict) or not isinstance(document.get('jobs'), dict):
        raise ValueError('Workflow must declare jobs')
    if 'concurrency' in document:
        raise ValueError('Workflow concurrency can strand tag/pack preparation')
    jobs = document['jobs']
    for name in PREPARATION_JOBS:
        if name not in jobs:
            raise ValueError(f'Missing preparation job: {name}')
        if 'concurrency' in jobs[name]:
            raise ValueError(f'Preparation job must not queue behind a concurrency group: {name}')
    for name, job in jobs.items():
        uses = [job['uses']] if 'uses' in job else []
        uses.extend(step['uses'] for step in job.get('steps', []) if 'uses' in step)
        for action in uses:
            if action.startswith('./'):
                continue
            if action.startswith('docker://'):
                valid = re.fullmatch(r'docker://.+@sha256:[0-9a-f]{64}', action)
            else:
                valid = re.fullmatch(r'[^@\s]+/[\w./-]+@[0-9a-f]{40}', action)
            if not valid:
                raise ValueError(f'Action must use an immutable commit or image digest: {name}: {action}')
    # Pinning the rust-toolchain action removes its version-ref inference.
    for name, version in [('msrv', '1.88.0'), ('test', 'stable')]:
        steps = [step for step in jobs[name].get('steps', [])
                 if step.get('uses', '').startswith('dtolnay/rust-toolchain@')]
        if len(steps) != 1 or steps[0].get('with', {}).get('toolchain') != version:
            raise ValueError(f'Explicit Rust toolchain required for {name}')


def main():
    path = Path(__file__).resolve().parents[1]/'.github/workflows/ci.yml'
    check(yaml.safe_load(path.read_text()))
    print('Pinned actions and release preparation scheduling verified')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f'Workflow contract failed: {error}', file=sys.stderr)
        raise SystemExit(1) from None
