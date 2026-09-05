#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/state"

cat > "$tmp/gh" <<'EOF'
#!/bin/sh
case "$1 $2" in
  "workflow run")
    test "${MOCK_FAIL_DISPATCH:-0}" -eq 0 || exit 13
    printf '%s\n' "$*" > "$MOCK_STATE/dispatch"
    ;;
  "api repos/example/project/commits/main")
    printf '%s\n' "${MOCK_CURRENT_MAIN:-main-sha}"
    ;;
  "api repos/example/project/actions/workflows/packages.yml/runs?branch=main&per_page=100")
    test "${MOCK_FAIL_EXISTING_QUERY:-0}" -eq 0 || exit 14
    test -z "${MOCK_EXISTING_SHA:-}" || printf '39\t%s\n' "$MOCK_EXISTING_SHA"
    ;;
  "api repos/example/project/actions/workflows/packages.yml/runs?event=workflow_dispatch&per_page=50")
    test "${MOCK_FAIL_DISCOVERY_QUERY:-0}" -eq 0 || exit 15
    printf '%s\t%s\t%s\n' \
      41 "${MOCK_TITLE:-Publish packages / sync-release-700-2}" \
      "${MOCK_RUN_SHA:-main-sha}"
    ;;
  "api repos/example/project/actions/runs/41")
    count_file="$MOCK_STATE/polls"
    count=0
    test ! -e "$count_file" || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s\n' "$count" > "$count_file"
    if [ "${MOCK_CONCLUSION:-success}" = timeout ]; then
      printf 'in_progress|\n'
    elif [ "$count" -eq 1 ]; then
      printf 'in_progress|\n'
    else
      printf 'completed|%s\n' "${MOCK_CONCLUSION:-success}"
    fi
    ;;
  *) echo "unexpected gh invocation: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$tmp/gh"

run_helper() {
  PATH="$tmp:$PATH" \
  MOCK_STATE="$tmp/state" \
  GITHUB_RUN_ID=700 \
  GITHUB_RUN_ATTEMPT=2 \
  GITHUB_SERVER_URL=https://github.example \
  PENTECT_PACKAGE_RUN_DISCOVERY_DELAY=${PENTECT_PACKAGE_RUN_DISCOVERY_DELAY:-0} \
  PENTECT_PACKAGE_RUN_POLL_DELAY=${PENTECT_PACKAGE_RUN_POLL_DELAY:-0} \
  PENTECT_PACKAGE_RUN_POLL_ATTEMPTS=${PENTECT_PACKAGE_RUN_POLL_ATTEMPTS:-2} \
    sh "$root/tools/dispatch_package_site.sh" \
      example/project v1.2.3 release-sha "${MOCK_EXPECTED_MAIN:-main-sha}"
}

output=$(run_helper)
printf '%s\n' "$output" | grep -Fx \
  'APT site sync: https://github.example/example/project/actions/runs/41'
grep -F -- 'workflow run packages.yml --repo example/project --ref main -f tag=v1.2.3 -f correlation=release-700-2' \
  "$tmp/state/dispatch"
test "$(cat "$tmp/state/polls")" -eq 2

if MOCK_RUN_SHA=other-sha run_helper >/dev/null 2>"$tmp/mismatch"; then
  echo "unexpected success for a mismatched correlated run" >&2
  exit 1
fi
grep -F 'unexpected main commit' "$tmp/mismatch"

if MOCK_CONCLUSION=failure run_helper >/dev/null 2>"$tmp/failure"; then
  echo "unexpected success for a failed package run" >&2
  exit 1
fi
grep -F 'conclusion: failure' "$tmp/failure"

if MOCK_CONCLUSION=timeout run_helper >/dev/null 2>"$tmp/timeout"; then
  echo "unexpected success for a package run timeout" >&2
  exit 1
fi
grep -F 'timed out waiting' "$tmp/timeout"

if MOCK_CURRENT_MAIN=release-sha MOCK_EXPECTED_MAIN=release-sha \
  run_helper >/dev/null 2>"$tmp/no-advance"; then
  echo "unexpected success without a new main commit" >&2
  exit 1
fi
grep -F 'did not advance main' "$tmp/no-advance"

if MOCK_EXISTING_SHA=main-sha run_helper >/dev/null 2>"$tmp/duplicate"; then
  echo "unexpected success for a duplicate same-commit deployment" >&2
  exit 1
fi
grep -F 'refusing a duplicate Pages deployment' "$tmp/duplicate"

if MOCK_TITLE='Publish packages / sync-unrelated' \
  PENTECT_PACKAGE_RUN_DISCOVERY_ATTEMPTS=2 \
  run_helper >/dev/null 2>"$tmp/correlation"; then
  echo "unexpected success without the exact correlated run" >&2
  exit 1
fi
grep -F 'could not locate the correlated' "$tmp/correlation"

if PENTECT_PACKAGE_RUN_POLL_ATTEMPTS=invalid \
  run_helper >/dev/null 2>"$tmp/invalid-limit"; then
  echo "unexpected success with an invalid polling limit" >&2
  exit 1
fi
grep -F 'attempt limits must be positive integers' "$tmp/invalid-limit"

: > "$tmp/state/dispatch"
if MOCK_FAIL_EXISTING_QUERY=1 run_helper >/dev/null 2>"$tmp/query-failure"; then
  echo "unexpected success after a duplicate-run query failure" >&2
  exit 1
fi
test ! -s "$tmp/state/dispatch"

: > "$tmp/state/dispatch"
if MOCK_CURRENT_MAIN=advanced-sha run_helper >/dev/null 2>"$tmp/main-advanced"; then
  echo "unexpected success after main advanced" >&2
  exit 1
fi
grep -F 'main advanced after' "$tmp/main-advanced"
test ! -s "$tmp/state/dispatch"

: > "$tmp/state/dispatch"
if MOCK_FAIL_DISPATCH=1 run_helper >/dev/null 2>"$tmp/dispatch-failure"; then
  echo "unexpected success after dispatch failed" >&2
  exit 1
fi
test ! -s "$tmp/state/dispatch"

if MOCK_FAIL_DISCOVERY_QUERY=1 run_helper >/dev/null 2>"$tmp/discovery-failure"; then
  echo "unexpected success after a correlated-run query failure" >&2
  exit 1
fi
