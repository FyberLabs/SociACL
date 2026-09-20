# SociACL requires Node.js 24+. Node 20 and 22 are not supported.
# shellcheck shell=bash
if ! command -v node >/dev/null; then
  echo "SociACL requires Node.js 24 or later (node not found)" >&2
  exit 1
fi
node_major="$(node -p "process.versions.node.split('.')[0]")"
if [[ "${node_major}" -lt 24 ]]; then
  echo "SociACL requires Node.js 24 or later (found $(node -v))" >&2
  echo "Node 20 and 22 are not supported." >&2
  exit 1
fi
