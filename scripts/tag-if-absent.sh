#!/usr/bin/env bash
# Create refs/tags/<family>-v<version> at GITHUB_SHA when that ref is absent.
# master must be protected; otherwise this exits 0 without creating a tag (#60).
# A tag that already names another commit is left unchanged.
# Usage: tag-if-absent.sh <ids|sociacl> <package.json>
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

version="$(node -p "require('./${package_json}').version")"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "${family} version is not MAJOR.MINOR.PATCH: ${version}" >&2
  exit 1
fi
tag="${family}-v${version}"

if [[ -z "${GH_REPO:-}" || -z "${GITHUB_SHA:-}" || -z "${GH_TOKEN:-}" ]]; then
  echo "GH_REPO, GITHUB_SHA, and GH_TOKEN are required" >&2
  exit 1
fi

emit() {
  printf '%s=%s\n' "$1" "$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}

emit tag "$tag"

protected="$(gh api "repos/${GH_REPO}/branches/master" --jq .protected)"
if [[ "$protected" != "true" ]]; then
  echo "::notice title=Release tag skipped::master is not protected (#60). Not creating ${tag}; pack-${family} would refuse it."
  emit created false
  emit publish false
  exit 0
fi

set +e
resolved="$(github_tag_commit "$GH_REPO" "$tag")"
status=$?
set -e
case "$status" in
  0) ;;
  2)
    created="$(gh api --method POST "repos/${GH_REPO}/git/refs" \
      -f "ref=refs/tags/${tag}" \
      -f "sha=${GITHUB_SHA}")"
    created_sha="$(jq -r '.object.sha // empty' <<<"$created")"
    if [[ "$created_sha" != "$GITHUB_SHA" ]]; then
      echo "created ${tag} at ${created_sha:-missing}, not ${GITHUB_SHA}" >&2
      exit 1
    fi
    echo "created ${tag} at ${GITHUB_SHA}"
    emit created true
    emit publish true
    exit 0
    ;;
  *)
    exit 1
    ;;
esac

emit created false
if [[ "$resolved" == "$GITHUB_SHA" ]]; then
  echo "${tag} already points at ${GITHUB_SHA}"
  emit publish true
else
  echo "::notice title=Release tag unchanged::${tag} points at ${resolved}, not ${GITHUB_SHA}. The tag was not moved."
  emit publish false
fi
