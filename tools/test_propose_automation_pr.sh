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
  "workflow run") printf '%s\n' https://github.com/example/project/actions/runs/1 ;;
  "pr merge") printf '%s\n' 'merge scheduled' ;;
  *) echo "unexpected gh invocation: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$tmp/git" "$tmp/gh"

output=$(
  PATH="$tmp:$PATH" \
  GH_TOKEN=test-token \
  GITHUB_REPOSITORY=example/project \
    sh "$root/tools/propose_automation_pr.sh" \
      automation/test "test automation" "test body" 2>/dev/null
)
test "$output" = https://github.com/example/project/pull/1
