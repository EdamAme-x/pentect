#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/pentect-install-test.XXXXXX")
cleanup() { rm -rf "$temporary"; }
trap cleanup 0 HUP INT TERM

home="$temporary/home"
mkdir -p "$home/bin"

dry_run=$(HOME="$home" PATH="$home/bin:/usr/bin:/bin" PENTECT_INSTALL_DRY_RUN=1 \
  "$root/tools/install.sh" --version 1.2.3)
printf '%s\n' "$dry_run" | grep -F "install=$home/bin/pentect" >/dev/null

dry_run=$(HOME="$home" PATH="/usr/bin:/bin" PENTECT_INSTALL_DRY_RUN=1 \
  "$root/tools/install.sh" --version 1.2.3)
printf '%s\n' "$dry_run" | grep -F "install=$home/.local/bin/pentect" >/dev/null

fixture="$temporary/fixture"
mock_bin="$temporary/mock-bin"
mkdir -p "$fixture" "$mock_bin"
printf '%s\n' '#!/bin/sh' 'printf "pentect test\\n"' > "$fixture/pentect-linux-x86_64"
chmod 0755 "$fixture/pentect-linux-x86_64"
sha256sum "$fixture/pentect-linux-x86_64" > "$fixture/pentect-linux-x86_64.sha256"

sed "s|@FIXTURE@|$fixture|g" "$root/tools/testdata/install-curl.sh" > "$mock_bin/curl"
chmod 0755 "$mock_bin/curl"

rm -rf "$home/bin"
HOME="$home" SHELL=/bin/bash PATH="$mock_bin:/usr/bin:/bin" \
  "$root/tools/install.sh" --version 1.2.3 > "$temporary/first.log"
test -x "$home/.local/bin/pentect"
grep -F 'added to shell profile' "$temporary/first.log" >/dev/null
grep -F 'Run now:' "$temporary/first.log" >/dev/null

HOME="$home" SHELL=/bin/bash PATH="$mock_bin:/usr/bin:/bin" \
  "$root/tools/install.sh" --version 1.2.3 > "$temporary/second.log"
test "$(grep -F -c '# Added by the Pentect installer' "$home/.profile")" -eq 1
test "$(grep -F -c '# Added by the Pentect installer' "$home/.bashrc")" -eq 1

PATH=/usr/bin:/bin HOME="$home" sh -c '. "$HOME/.profile"; command -v pentect' \
  | grep -F "$home/.local/bin/pentect" >/dev/null

