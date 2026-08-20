#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cat > "$tmp/git" <<'EOF'
#!/bin/sh
if [ "$1 $2" = "rev-parse HEAD" ]; then
  printf '%s\n' 0123456789abcdef
fi
EOF
cat > "$tmp/gh" <<'EOF'
#!/bin/sh
case "$1 $2" in
  "pr list") exit 0 ;;
  "pr create") printf '%s\n' https://github.com/example/project/pull/1 ;;
  "pr merge") printf '%s\n' 'merge scheduled' ;;
  "workflow run")
    case "$*" in
      *ci.yml*) touch "$MOCK_STATE/ci" ;;
      *nix.yml*) touch "$MOCK_STATE/nix" ;;
    esac
    ;;
  "run list")
    case "$*" in
      *ci.yml*) test ! -e "$MOCK_STATE/ci" || printf '%s\n' 101 ;;
      *nix.yml*) test ! -e "$MOCK_STATE/nix" || printf '%s\n' 102 ;;
    esac
    ;;
  "run watch") printf '%s\n' "$*" >> "$MOCK_STATE/watch" ;;
  "api --method") printf '%s\n' "$*" >> "$MOCK_STATE/api" ;;
  *) echo "unexpected gh invocation: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$tmp/git" "$tmp/gh"
mkdir "$tmp/state"

output=$(
  PATH="$tmp:$PATH" \
  MOCK_STATE="$tmp/state" \
  GH_TOKEN=test-token \
  GITHUB_REPOSITORY=example/project \
    sh "$root/tools/propose_automation_pr.sh" \
      automation/test "test automation" "test body" 2>/dev/null
)
test "$output" = https://github.com/example/project/pull/1
test "$(wc -l < "$tmp/state/watch")" -eq 2
grep -Fx 'run watch 101 --repo example/project --exit-status' "$tmp/state/watch"
grep -Fx 'run watch 102 --repo example/project --exit-status' "$tmp/state/watch"
test "$(wc -l < "$tmp/state/api")" -eq 3
status_endpoint='api --method POST repos/example/project/statuses/0123456789abcdef'
test "$(grep -Fc "$status_endpoint" "$tmp/state/api")" -eq 3
grep -F 'context=test' "$tmp/state/api"
grep -F 'context=Native OCR (windows-latest)' "$tmp/state/api"
grep -F 'context=Native OCR (macos-latest)' "$tmp/state/api"
test "$(grep -Fc 'target_url=https://github.com/example/project/actions/runs/101' "$tmp/state/api")" -eq 3
