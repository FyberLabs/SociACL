// Each native JUnit case is an executed owner harness, never a setup-only pass.
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

if (process.env.GITHUB_ACTIONS !== 'true' || process.env.GITHUB_EVENT_NAME !== 'schedule' ||
    process.env.NIGHTLY_SUITE !== 'sociacl-browser' || process.env.GITHUB_REPOSITORY !== 'FyberLabs/SociACL') {
  throw new Error('Integration execution requires the central Infra nightly batch');
}
const root = fileURLToPath(new URL('../', import.meta.url));
const cases = [
  ['rust-c-python-runtime', 'bash', ['scripts/test-runtime.sh']],
  ['installed-identity-consumer', 'npm', ['--prefix', 'typescript/ids', 'run', 'consumer']],
  ...['browser-store', 'browser-client', 'browser-checkpoint-store', 'browser-checkpoint-client']
    .map(name => [name, process.execPath, [`typescript/ids/scripts/${name}.mjs`]]),
];
for (const [name, command, args] of cases) {
  test(name, () => {
    try {
      execFileSync(command, args, { cwd: root, stdio: 'pipe', maxBuffer: 4 * 1024 * 1024 });
    } catch (error) {
      // Infra redacts this stream; native XML keeps only the case outcome.
      process.stderr.write(error.stdout ?? '');
      process.stderr.write(error.stderr ?? '');
      throw new Error(`${name} failed (status ${error.status ?? 'signal'})`);
    }
  });
}
