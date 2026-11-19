## Mandatory agent worktrees

The owner explicitly authorizes agents to create task worktrees and local
task branches without asking. Before editing, create or reuse a dedicated
worktree for your task. Create new worktrees from the freshly fetched remote
default branch. Use the Codex worktree tool when available.

The primary checkout is for read-only inspection and fetching. Do all edits,
builds, tests and commits in the task worktree. Keep other agents' worktrees
and existing local changes intact. If worktree setup fails, resolve it or
report the blocker before editing.

## Git preflight

At the start of work in each repository, run `git status --short --branch`
and fetch the remote default branch before relying on local files. For an
`origin` remote with a `main` default branch, run `git fetch origin main`.
Use the actual remote and default branch when they differ. Check whether
your branch has diverged from the fetched default branch and inspect upstream
changes relevant to the task. If the fetch fails, report the limitation before
relying on stale local configuration.

Base new task branches on the freshly fetched default branch. For existing
work, preserve local edits and commits. Read current files from the fetched
ref when needed.

## Shared TEST and production configuration

Start with `FyberLabs/infra` on its current default branch. Read its
`AGENTS.md` configuration rules and `docs/CONFIG.md`, then look in
`config/manifest.yaml`, `config/environments/` and the relevant fixture
declarations. Recover and reuse existing deployment facts, credential
references and fixtures. Put new shared declarations and repeatable
provisioning in Infra, and keep component-owned fixtures with their owner.
Use the canonical secret store for credential values. Ask the owner only
for the exact external action or authority you lack.
