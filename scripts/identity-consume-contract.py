#!/usr/bin/env python3
"""Snapshot canonical declaration output and vector hashes; default is read-only."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'docs/identity-consume'
# No optional Zod dependency, browser persistence implementation, or runtime JS.
FILES = ('index.d.ts', 'types.d.ts', 'ids.d.ts', 'records.d.ts', 'json.d.ts',
         'util.d.ts', 'witness-policy.d.ts', 'witness-checkpoint.d.ts', 'agent-delegation.d.ts', 'reader-wrap.d.ts')


def snapshot():
    files = {name: (ROOT/'typescript/ids/dist'/name).read_bytes() for name in FILES}
    hashes = {f'docs/identity-consume/{name}': hashlib.sha256(data).hexdigest()
              for name, data in files.items()}
    for directory in ('vectors/ids', 'vectors/mesh', 'vectors/agent-delegation', 'vectors/first-contact'):
        for path in sorted((ROOT/directory).rglob('*.json')):
            hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ('wrap.json', 'sea-fixture.json'):
        path = ROOT/'vectors/encrypted-discovery'/name
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    hashes['docs/s3rch-check.d.ts'] = hashlib.sha256((ROOT/'docs/s3rch-check.d.ts').read_bytes()).hexdigest()
    hashes['docs/first-contact.d.ts'] = hashlib.sha256((ROOT/'docs/first-contact.d.ts').read_bytes()).hexdigest()
    manifest = {'schema': 1, 'contract': 'sociacl-identity-consume-v1',
                'packageVersion': json.loads((ROOT/'typescript/ids/package.json').read_text())['version'],
                'sha256': dict(sorted(hashes.items()))}
    files['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    expected = snapshot()
    if args.write:
        TARGET.mkdir(parents=True, exist_ok=True)
        for name, data in expected.items():
            (TARGET/name).write_bytes(data)
    else:
        changed = [name for name, data in expected.items()
                   if not (TARGET/name).exists() or (TARGET/name).read_bytes() != data]
        unexpected = {p.name for p in TARGET.glob('*.d.ts')} - set(FILES)
        if changed or unexpected:
            raise SystemExit('Identity consume snapshot drift: ' + ', '.join(sorted(set(changed) | unexpected)))
        print('Identity consume declarations and shared vector hashes match')


if __name__ == '__main__':
    main()
