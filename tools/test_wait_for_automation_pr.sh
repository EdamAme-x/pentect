#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/state"

cat > "$tmp/git" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_STATE/git"
EOF
cat > "$tmp/gh" <<'EOF'
#!/bin/sh
case "$1 $2" in
  "pr view")
    count_file="$MOCK_STATE/views"
    count=0
    test ! -e "$count_file" || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s\n' "$count" > "$count_file"
    if [ "$count" -eq 1 ]; then
      printf '%s\n' '{"state":"OPEN","mergeStateStatus":"BEHIND"}'
    else
      printf '%s\n' '{"state":"MERGED","mergeStateStatus":"UNKNOWN"}'
    fi
    ;;
  "pr merge") printf '%s\n' "$*" >> "$MOCK_STATE/gh" ;;
  *) echo "unexpected gh invocation: $*" >&2; exit 1 ;;
esac
EOF
cat > "$tmp/propose" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_STATE/propose"
printf '%s\n' https://github.com/example/project/pull/7
EOF
cat > "$tmp/jq" <<'EOF'
#!/bin/sh
input=$(cat)
case "$2" in
  .state) printf '%s\n' "$input" | sed -n 's/.*"state":"\([^"]*\)".*/\1/p' ;;
  .mergeStateStatus) printf '%s\n' "$input" | sed -n 's/.*"mergeStateStatus":"\([^"]*\)".*/\1/p' ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$tmp/git" "$tmp/gh" "$tmp/propose" "$tmp/jq"

output=$(
  PATH="$tmp:$PATH" \
  MOCK_STATE="$tmp/state" \
  GITHUB_REPOSITORY=example/project \
  PENTECT_AUTOMATION_PR_WAIT_ATTEMPTS=3 \
  PENTECT_AUTOMATION_PR_WAIT_SECONDS=0 \
  PENTECT_PROPOSE_AUTOMATION_PR="$tmp/propose" \
    sh "$root/tools/wait_for_automation_pr.sh" \
      https://github.com/example/project/pull/7 \
      automation/test \
      "test title" \
      "test body" 2>/dev/null
)

test "$output" = https://github.com/example/project/pull/7
grep -Fx 'pr merge https://github.com/example/project/pull/7 --repo example/project --disable-auto' "$tmp/state/gh"
grep -Fx 'fetch origin main --no-tags' "$tmp/state/git"
grep -Fx 'rebase origin/main' "$tmp/state/git"
grep -Fx 'automation/test test title test body' "$tmp/state/propose"
test "$(cat "$tmp/state/views")" -eq 2
