#!/bin/sh
set -eu
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
mkdir "$root/bin"
cat >"$root/bin/npm" <<'EOF'
#!/bin/sh
test "$1" = view
test "$3" = version
case " $* " in *' --prefer-online '*) :;; *) exit 97;; esac
case " $* " in *' --registry=https://registry.npmjs.org '*) :;; *) exit 97;; esac
case " $* " in *' --fetch-retries=0 '*) :;; *) exit 97;; esac
case " $* " in *' --fetch-timeout=5000 '*) :;; *) exit 97;; esac
count=0; test ! -f "$FAKE_NPM_COUNT" || count=$(cat "$FAKE_NPM_COUNT")
count=$((count + 1)); printf '%s\n' "$count" >"$FAKE_NPM_COUNT"
case "$FAKE_NPM_MODE" in
  transient) test "$count" -ge 3 && { echo "$FAKE_NPM_VERSION"; exit 0; }; echo 'npm error code E404' >&2; exit 1;;
  missing) echo 'npm error 404 Not Found' >&2; exit 1;;
  auth401) echo 'npm error code E401' >&2; exit 1;;
  auth403) echo 'npm error code E403' >&2; exit 1;;
  network) echo 'npm error code E503' >&2; exit 1;;
  wrong) echo '9.9.9'; exit 0;;
esac
EOF
chmod +x "$root/bin/npm"
export PATH="$root/bin:$PATH" RUNNER_TEMP="$root" FAKE_NPM_COUNT="$root/count" FAKE_NPM_VERSION=1.2.3
FAKE_NPM_MODE=transient; export FAKE_NPM_MODE
tools/wait_for_npm_version.sh pentect 1.2.3 3 0
test "$(cat "$FAKE_NPM_COUNT")" = 3
rm -f "$FAKE_NPM_COUNT"; FAKE_NPM_MODE=missing; export FAKE_NPM_MODE
if tools/wait_for_npm_version.sh pentect 1.2.3 2 0 >"$root/out" 2>"$root/err"; then exit 1; else status=$?; fi
test "$status" = 4; test "$(cat "$FAKE_NPM_COUNT")" = 2; grep -q 'still not visible' "$root/err"
rm -f "$FAKE_NPM_COUNT"; FAKE_NPM_MODE=auth401; export FAKE_NPM_MODE
if tools/wait_for_npm_version.sh pentect 1.2.3 3 0 >"$root/out" 2>"$root/err"; then exit 1; else status=$?; fi
test "$status" = 1; test "$(cat "$FAKE_NPM_COUNT")" = 1; grep -q E401 "$root/err"
rm -f "$FAKE_NPM_COUNT"; FAKE_NPM_MODE=auth403; export FAKE_NPM_MODE
if tools/wait_for_npm_version.sh pentect 1.2.3 3 0 >"$root/out" 2>"$root/err"; then exit 1; else status=$?; fi
test "$status" = 1; test "$(cat "$FAKE_NPM_COUNT")" = 1; grep -q E403 "$root/err"
rm -f "$FAKE_NPM_COUNT"; FAKE_NPM_MODE=network; export FAKE_NPM_MODE
if tools/wait_for_npm_version.sh pentect 1.2.3 3 0 >"$root/out" 2>"$root/err"; then exit 1; else status=$?; fi
test "$status" = 1; test "$(cat "$FAKE_NPM_COUNT")" = 1; grep -q E503 "$root/err"
rm -f "$FAKE_NPM_COUNT"; FAKE_NPM_MODE=wrong; export FAKE_NPM_MODE
if tools/wait_for_npm_version.sh pentect 1.2.3 3 0 >"$root/out" 2>"$root/err"; then exit 1; else status=$?; fi
test "$status" = 1; test "$(cat "$FAKE_NPM_COUNT")" = 1; grep -q 'unexpected version' "$root/err"
