#!/usr/bin/env bash
# Resolve a lightweight or annotated tag to the commit it names.
# Prints the commit and returns 0, returns 2 when the tag is absent,
# and returns 1 on any other error. Callers decide whether absence is fatal.
# shellcheck shell=bash

github_tag_commit() {
  local repo="$1"
  local tag="$2"
  local lookup err_file status err object_type object_sha

  err_file="$(mktemp)"
  if lookup="$(gh api "repos/${repo}/git/ref/tags/${tag}" 2>"$err_file")"; then
    status=0
  else
    status=$?
  fi
  err="$(cat "$err_file")"
  rm -f "$err_file"

  if [[ "$status" -ne 0 ]]; then
    if [[ "$err" == *"HTTP 404"* || "$lookup" == *'"status":"404"'* ]]; then
      return 2
    fi
    printf '%s\n%s\n' "$err" "$lookup" >&2
    return 1
  fi

  object_type="$(jq -r '.object.type // empty' <<<"$lookup")" || return 1
  object_sha="$(jq -r '.object.sha // empty' <<<"$lookup")" || return 1
  if [[ "$object_type" == "tag" ]]; then
    if ! object_sha="$(gh api "repos/${repo}/git/tags/${object_sha}" --jq .object.sha)"; then
      echo "failed to peel tag ${tag}" >&2
      return 1
    fi
  elif [[ "$object_type" != "commit" ]]; then
    echo "tag ${tag} object type ${object_type:-missing} is not a commit" >&2
    return 1
  fi
  if [[ ! "$object_sha" =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "tag ${tag} did not resolve to a commit" >&2
    return 1
  fi
  printf '%s\n' "$object_sha"
}
