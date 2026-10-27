#!/usr/bin/env bash
# Fail closed unless RELEASE_TAG may be packed from this commit.
# master must be protected, the commit must be on origin/master, and the tag
# must be <family>-v<package version> resolved to GITHUB_SHA.
# Usage: verify-release-ref.sh <ids|sociacl> <package.json>
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/github-tag.sh
. "${root}/scripts/github-tag.sh"

family="${1:?family}"
package_json="${2:?package.json}"

case "$family" in
  ids|sociacl) ;;
  *)
    echo "unknown release family: ${family}" >&2
    exit 1
    ;;
esac

if [[ -z "${GH_REPO:-}" || -z "${GITHUB_SHA:-}" || -z "${GH_TOKEN:-}" || -z "${RELEASE_TAG:-}" ]]; then
  echo "GH_REPO, GITHUB_SHA, GH_TOKEN, and RELEASE_TAG are required" >&2
  exit 1
fi

if ! git merge-base --is-ancestor "$GITHUB_SHA" origin/master; then
  echo "${RELEASE_TAG} commit ${GITHUB_SHA} is not an ancestor of origin/master" >&2
  exit 1
fi

protected="$(gh api "repos/${GH_REPO}/branches/master" --jq .protected)"
if [[ "$protected" != "true" ]]; then
  echo "master is not protected; refusing to pack ${family} (#60)" >&2
  exit 1
fi

version="$(node -p "require('./${package_json}').version")"
expected="${family}-v${version}"
if [[ "$RELEASE_TAG" != "$expected" ]]; then
  echo "tag ${RELEASE_TAG} does not match ${expected}" >&2
  exit 1
fi

set +e
resolved="$(github_tag_commit "$GH_REPO" "$RELEASE_TAG")"
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
  echo "tag ${RELEASE_TAG} does not resolve to a commit" >&2
  exit 1
fi
if [[ "$resolved" != "$GITHUB_SHA" ]]; then
  echo "tag ${RELEASE_TAG} points at ${resolved}, not ${GITHUB_SHA}" >&2
  exit 1
fi
echo "${RELEASE_TAG} resolves to ${GITHUB_SHA}"
