// The reusable Infra runner projects the checked-out suite's repository.
export function requireInfraNightly(env = process.env) {
  const authorizedEvent = env.GITHUB_EVENT_NAME === 'schedule' ||
    (env.GITHUB_EVENT_NAME === 'workflow_dispatch' &&
      env.GITHUB_ACTOR === 'cchamilt' && env.GITHUB_TRIGGERING_ACTOR === 'cchamilt');
  if (env.GITHUB_ACTIONS !== 'true' || !authorizedEvent ||
      env.GITHUB_WORKFLOW_REF !== 'FyberLabs/infra/.github/workflows/nightly-integration.yml@refs/heads/main' ||
      env.NIGHTLY_SUITE !== 'sociacl-browser' || env.GITHUB_REPOSITORY !== 'FyberLabs/SociACL') {
    throw new Error('Integration execution requires the central Infra nightly batch');
  }
}
