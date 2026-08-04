#!/bin/sh
set -eu

repository_url="https://pentect.dev/apt"
key_url="https://pentect.dev/apt/pentect-archive-keyring.asc"
key_sha256="d6d59be8b1d87fa731577f52d98a604f2687bf97f6c5e1981dd805e78a7ff7ac"

if [ "$(id -u)" -ne 0 ]; then
  echo "pentect: run this installer as root (for example, pipe it to sudo sh)" >&2
  exit 1
fi
command -v apt-get >/dev/null 2>&1 || { echo "pentect: apt-get is required" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "pentect: curl is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "pentect: sha256sum is required" >&2; exit 1; }

architecture=$(dpkg --print-architecture)
case "$architecture" in
  amd64|arm64) ;;
  *) echo "pentect: unsupported Debian architecture: $architecture" >&2; exit 1 ;;
esac

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/pentect-apt.XXXXXX")
cleanup() { rm -rf "$temp_dir"; }
trap cleanup 0 HUP INT TERM

printf 'Pentect apt installer\n'
printf '  Architecture : %s\n\n' "$architecture"
printf '[1/4] Downloading archive key...\n'
curl -fsSL --proto '=https' --tlsv1.2 "$key_url" -o "$temp_dir/key.asc"
actual=$(sha256sum "$temp_dir/key.asc" | awk '{ print tolower($1) }')
if [ "$actual" != "$key_sha256" ]; then
  echo "pentect: archive key checksum mismatch" >&2
  exit 1
fi

printf '[2/4] Configuring signed repository...\n'
install -d -m 0755 /etc/apt/keyrings
install -m 0644 "$temp_dir/key.asc" /etc/apt/keyrings/pentect-archive-keyring.asc
cat > /etc/apt/sources.list.d/pentect.sources <<EOF
Types: deb
URIs: $repository_url
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/pentect-archive-keyring.asc
EOF

printf '[3/4] Refreshing package index...\n'
apt-get update
printf '[4/4] Installing Pentect...\n'
DEBIAN_FRONTEND=noninteractive apt-get install -y pentect
printf '\nInstalled Pentect with apt.\n'
printf 'Next: pentect doctor\n'
