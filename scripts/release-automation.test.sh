#!/usr/bin/env bash
# State-machine tests for tag-if-absent and the pack-time ref gate.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
other="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
peeled="cccccccccccccccccccccccccccccccccccccccc"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/work"
cat >"$tmp/work/package.json" <<'EOF'
{ "name": "sociacl-ids", "version": "0.10.0" }
EOF

cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${TAG_TEST_LOG}"
args="$*"
scenario="${TAG_TEST_SCENARIO}"

if [[ "$args" == *"/branches/master"* ]]; then
  case "$scenario" in
    unprotected) printf '%s\n' false ;;
    api-down)
      echo "gh: Bad Gateway (HTTP 502)" >&2
      exit 1
      ;;
    *) printf '%s\n' true ;;
  esac
  exit 0
fi

if [[ "$args" == *"release view"* ]]; then
  case "$scenario" in
    release-exists) exit 0 ;;
    release-absent)
      echo "release not found" >&2
      exit 1
      ;;
    release-down)
      echo "gh: Bad Gateway (HTTP 502)" >&2
      exit 1
      ;;
    *)
      echo "unhandled release view scenario ${scenario}" >&2
      exit 1
      ;;
  esac
fi

if [[ "$args" == *"--method POST"* ]]; then
  case "$scenario" in
    post-mismatch)
      printf '{"object":{"sha":"%s","type":"commit"}}\n' "$TAG_TEST_OTHER"
      ;;
    post-fail)
      echo "gh: Internal Server Error (HTTP 500)" >&2
      printf '%s\n' '{"status":"500"}'
      exit 1
      ;;
    *)
      posted=""
      for arg in "$@"; do
        case "$arg" in
          sha=*) posted="${arg#sha=}" ;;
        esac
      done
      printf '{"object":{"sha":"%s","type":"commit"}}\n' "$posted"
      ;;
  esac
  exit 0
fi

if [[ "$args" == *"/git/tags/"* ]]; then
  case "$scenario" in
    annotated-same) printf '%s\n' "$TAG_TEST_SHA" ;;
    annotated-other) printf '%s\n' "$TAG_TEST_OTHER" ;;
    *)
      echo "unexpected peel for ${scenario}" >&2
      exit 1
      ;;
  esac
  exit 0
fi

if [[ "$args" == *"/git/ref/tags/"* ]]; then
  case "$scenario" in
    absent)
      printf '%s\n' '{"message":"Not Found","status":"404"}'
      echo "gh: Not Found (HTTP 404)" >&2
      exit 1
      ;;
    same)
      printf '{"object":{"sha":"%s","type":"commit"}}\n' "$TAG_TEST_SHA"
      ;;
    other)
      printf '{"object":{"sha":"%s","type":"commit"}}\n' "$TAG_TEST_OTHER"
      ;;
    annotated-same|annotated-other)
      printf '{"object":{"sha":"%s","type":"tag"}}\n' "$TAG_TEST_PEELED"
      ;;
    server-error)
      printf '%s\n' '{"status":"500"}'
      echo "gh: Internal Server Error (HTTP 500)" >&2
      exit 1
      ;;
    *)
      echo "unhandled ref lookup scenario ${scenario}" >&2
      exit 1
      ;;
  esac
  exit 0
fi

echo "unhandled gh invocation: ${args}" >&2
exit 1
EOF
chmod +x "$tmp/bin/gh"

export PATH="${tmp}/bin:${PATH}"
export GH_REPO="FyberLabs/SociACL"
export GH_TOKEN="test-token"
export GITHUB_SHA="$sha"
export TAG_TEST_SHA="$sha"
export TAG_TEST_OTHER="$other"
export TAG_TEST_PEELED="$peeled"

assert_eq() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "${label}: got ${got}, want ${want}" >&2
    exit 1
  fi
}

output_of() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1) }' "$GITHUB_OUTPUT"
}

run_tag() {
  local scenario="$1"
  local family="${2:-ids}"
  export TAG_TEST_SCENARIO="$scenario"
  export TAG_TEST_LOG="${tmp}/gh.log"
  export GITHUB_OUTPUT="${tmp}/outputs"
  : >"$TAG_TEST_LOG"
  : >"$GITHUB_OUTPUT"
  set +e
  (cd "$tmp/work" && bash "${root}/scripts/tag-if-absent.sh" "$family" package.json >"$tmp/stdout" 2>"$tmp/stderr")
  status=$?
  set -e
}

run_tag absent
assert_eq "$status" 0 "absent status"
assert_eq "$(output_of tag)" "ids-v0.10.0" "absent tag"
assert_eq "$(output_of created)" true "absent created"
assert_eq "$(output_of publish)" true "absent publish"
grep -q 'ref=refs/tags/ids-v0.10.0' "$TAG_TEST_LOG"
grep -q "sha=${sha}" "$TAG_TEST_LOG"

run_tag same
assert_eq "$status" 0 "same status"
assert_eq "$(output_of created)" false "same created"
assert_eq "$(output_of publish)" true "same publish"
if grep -q -- '--method POST' "$TAG_TEST_LOG"; then
  echo "same-commit tag issued a create" >&2
  exit 1
fi

run_tag other
assert_eq "$status" 0 "other status"
assert_eq "$(output_of created)" false "other created"
assert_eq "$(output_of publish)" false "other publish"
if grep -q -- '--method POST' "$TAG_TEST_LOG"; then
  echo "foreign tag was moved" >&2
  exit 1
fi
grep -q 'Release tag unchanged' "$tmp/stdout"

run_tag annotated-same
assert_eq "$status" 0 "annotated-same status"
assert_eq "$(output_of publish)" true "annotated-same publish"
assert_eq "$(output_of created)" false "annotated-same created"

run_tag annotated-other
assert_eq "$status" 0 "annotated-other status"
assert_eq "$(output_of publish)" false "annotated-other publish"

run_tag unprotected
assert_eq "$status" 0 "unprotected status"
assert_eq "$(output_of created)" false "unprotected created"
assert_eq "$(output_of publish)" false "unprotected publish"
grep -q 'master is not protected' "$tmp/stdout"
if grep -q '/git/ref/tags/' "$TAG_TEST_LOG"; then
  echo "unprotected master looked up a tag" >&2
  exit 1
fi
if grep -q -- '--method POST' "$TAG_TEST_LOG"; then
  echo "unprotected master created a tag" >&2
  exit 1
fi

run_tag server-error
assert_eq "$status" 1 "server-error status"
if grep -q -- '--method POST' "$TAG_TEST_LOG"; then
  echo "server error created a tag" >&2
  exit 1
fi

run_tag api-down
assert_eq "$status" 1 "api-down status"

run_tag post-mismatch
assert_eq "$status" 1 "post-mismatch status"

run_tag post-fail
assert_eq "$status" 1 "post-fail status"

run_tag absent sociacl
assert_eq "$status" 0 "sociacl status"
assert_eq "$(output_of tag)" "sociacl-v0.10.0" "sociacl tag"
grep -q 'ref=refs/tags/sociacl-v0.10.0' "$TAG_TEST_LOG"

printf '%s\n' '{ "name": "sociacl-ids", "version": "0.10" }' >"$tmp/work/package.json"
run_tag absent
assert_eq "$status" 1 "bad-version status"
if [[ -s "$TAG_TEST_LOG" ]]; then
  echo "bad version called gh" >&2
  exit 1
fi
printf '%s\n' '{ "name": "sociacl-ids", "version": "0.10.0" }' >"$tmp/work/package.json"

run_tag absent nope
assert_eq "$status" 1 "bad-family status"

# Pack refuses an unprotected master, a foreign tag, a missing tag, and a
# commit that is not on origin/master. It accepts a tag that peels to HEAD.
repo="$(mktemp -d)"
git -C "$repo" init -q -b master
git -C "$repo" config user.email test@example.com
git -C "$repo" config user.name test
cp "$tmp/work/package.json" "$repo/package.json"
git -C "$repo" add package.json
git -C "$repo" commit -q -m init
git -C "$repo" update-ref refs/remotes/origin/master HEAD
head_sha="$(git -C "$repo" rev-parse HEAD)"

run_verify() {
  local scenario="$1"
  export TAG_TEST_SCENARIO="$scenario"
  export TAG_TEST_LOG="${tmp}/verify-gh.log"
  export GITHUB_SHA="$head_sha"
  export TAG_TEST_SHA="$head_sha"
  : >"$TAG_TEST_LOG"
  set +e
  (cd "$repo" && RELEASE_TAG=ids-v0.10.0 bash "${root}/scripts/verify-release-ref.sh" ids package.json >"$tmp/verify-out" 2>"$tmp/verify-err")
  status=$?
  set -e
}

run_verify same
assert_eq "$status" 0 "verify same status"

run_verify unprotected
assert_eq "$status" 1 "verify unprotected status"
grep -q 'refusing to pack' "$tmp/verify-err"

run_verify other
assert_eq "$status" 1 "verify other status"
grep -q 'points at' "$tmp/verify-err"

run_verify absent
assert_eq "$status" 1 "verify absent status"

run_verify annotated-same
assert_eq "$status" 0 "verify annotated status"

git -C "$repo" checkout -q -b side
git -C "$repo" commit -q --allow-empty -m side
side_sha="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q master
export TAG_TEST_SCENARIO=same
export GITHUB_SHA="$side_sha"
export TAG_TEST_SHA="$side_sha"
set +e
(cd "$repo" && RELEASE_TAG=ids-v0.10.0 bash "${root}/scripts/verify-release-ref.sh" ids package.json >"$tmp/verify-out" 2>"$tmp/verify-err")
status=$?
set -e
assert_eq "$status" 1 "verify not-ancestor status"
grep -q 'not an ancestor' "$tmp/verify-err"

# Version sources agree on this tree, and a drifted copy fails closed.
python3 "${root}/scripts/check-release-versions.py" >"$tmp/versions"

fixture="$(mktemp -d)"
mkdir -p "$fixture/typescript/ids" "$fixture/crates"
cp "$root/Cargo.toml" "$root/Cargo.lock" "$fixture/"
cp "$root/typescript/package.json" "$root/typescript/package-lock.json" "$fixture/typescript/"
cp "$root/typescript/ids/package.json" "$root/typescript/ids/package-lock.json" "$fixture/typescript/ids/"
while IFS= read -r member; do
  mkdir -p "$fixture/$member"
  cp "$root/$member/Cargo.toml" "$fixture/$member/Cargo.toml"
done < <(python3 -c 'import sys, tomllib; print("\n".join(tomllib.load(open(sys.argv[1], "rb"))["workspace"]["members"]))' "${root}/Cargo.toml")
python3 - "$fixture/typescript/package.json" <<'PY'
import json
import sys
path = sys.argv[1]
data = json.loads(open(path, encoding="utf-8").read())
data["version"] = "9.9.9"
open(path, "w", encoding="utf-8").write(json.dumps(data))
PY
set +e
CHECK_RELEASE_ROOT="$fixture" python3 "${root}/scripts/check-release-versions.py" >"$tmp/drift-out" 2>"$tmp/drift-err"
status=$?
set -e
assert_eq "$status" 1 "drifted sociacl version status"
grep -q 'sociacl-v versions differ' "$tmp/drift-err"
rm -rf "$fixture"

echo "release automation checks passed"
