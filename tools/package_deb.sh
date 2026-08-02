#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: package_deb.sh VERSION ARCH BINARY OUTPUT_DIR" >&2
  exit 2
fi

version=${1#v}
architecture=$2
binary=$3
output_dir=$4
case "$version" in
  *[!0-9A-Za-z.+~-]*|'') echo "invalid Debian version: $version" >&2; exit 2 ;;
esac
case "$architecture" in
  amd64|arm64) ;;
  *) echo "unsupported Debian architecture: $architecture" >&2; exit 2 ;;
esac
test -f "$binary" || { echo "missing binary: $binary" >&2; exit 2; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/pentect-deb.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup 0 HUP INT TERM

root="$work/root"
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/doc/pentect"
install -m 0755 "$binary" "$root/usr/bin/pentect"
cat > "$root/usr/bin/.pentect-managed-install.json" <<'EOF'
{"version":1,"manager":"apt","update":"sudo apt update && sudo apt install --only-upgrade pentect","uninstall":"sudo apt remove pentect"}
EOF
chmod 0644 "$root/usr/bin/.pentect-managed-install.json"
install -m 0644 LICENSE "$root/usr/share/doc/pentect/copyright"
install -m 0644 THIRD_PARTY_LICENSES.txt "$root/usr/share/doc/pentect/THIRD_PARTY_LICENSES.txt"

depends="ca-certificates, libc6 (>= 2.35), libgcc-s1"
cat > "$root/DEBIAN/control" <<EOF
Package: pentect
Version: $version
Section: utils
Priority: optional
Architecture: $architecture
Maintainer: EdamAme-x <edame8080@gmail.com>
Depends: $depends
Homepage: https://github.com/EdamAme-x/pentect
Description: Local secret masking boundary for AI agents
 Pentect masks secrets at AI tool and HTTP boundaries while keeping the
 original values local.
EOF

mkdir -p "$output_dir"
package="$output_dir/pentect_${version}_${architecture}.deb"
dpkg-deb --root-owner-group --build "$root" "$package"
sha256sum "$package" > "$package.sha256"
printf '%s\n' "$package"
