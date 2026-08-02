#!/bin/sh
set -eu

repository="EdamAme-x/pentect"
version=${PENTECT_VERSION:-}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || { echo "pentect: --version requires a value" >&2; exit 1; }
      version=$2
      shift 2
      ;;
    *)
      echo "pentect: unknown installer option: $1" >&2
      exit 1
      ;;
  esac
done
if [ -n "$version" ]; then
  version=${version#v}
  if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
    echo "pentect: invalid version: $version" >&2
    exit 1
  fi
  release_tag="v$version"
  base_url="https://github.com/$repository/releases/download/$release_tag"
else
  release_tag="latest"
  base_url="https://github.com/$repository/releases/latest/download"
fi

os=$(uname -s)
arch=$(uname -m)
case "$os:$arch" in
  Linux:x86_64|Linux:amd64)
    asset="pentect-linux-x86_64"
    ;;
  Linux:arm64|Linux:aarch64)
    asset="pentect-linux-aarch64"
    ;;
  Darwin:x86_64|Darwin:amd64)
    asset="pentect-macos-x86_64"
    ;;
  Darwin:arm64|Darwin:aarch64)
    asset="pentect-macos-aarch64"
    ;;
  *)
    echo "pentect: unsupported platform: $os/$arch" >&2
    exit 1
    ;;
esac

install_dir=${PENTECT_INSTALL_DIR:-"$HOME/.local/bin"}
destination="$install_dir/pentect"
marker="$install_dir/.pentect-managed-install.json"

if [ "${PENTECT_INSTALL_DRY_RUN:-0}" = "1" ]; then
  printf 'asset=%s\ninstall=%s\n' "$asset" "$destination"
  printf 'version=%s\n' "$release_tag"
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "pentect: curl is required" >&2
  exit 1
fi

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/pentect-install.XXXXXX")
cleanup() {
  rm -rf "$temp_dir"
}
trap cleanup 0 HUP INT TERM

printf 'Pentect installer\n'
printf '  Platform : %s/%s\n' "$os" "$arch"
printf '  Version  : %s\n' "$release_tag"
printf '  Install  : %s\n\n' "$destination"

printf '[1/4] Downloading %s...\n' "$release_tag"
curl -fsSL --proto '=https' --tlsv1.2 \
  "$base_url/$asset" \
  -o "$temp_dir/$asset"
curl -fsSL --proto '=https' --tlsv1.2 \
  "$base_url/$asset.sha256" \
  -o "$temp_dir/$asset.sha256"

printf '[2/4] Verifying SHA-256...\n'
expected=$(awk 'NR == 1 { print tolower($1) }' "$temp_dir/$asset.sha256")
case "$expected" in
  *[!0-9a-f]*|'')
    echo "pentect: release checksum is invalid" >&2
    exit 1
    ;;
esac
if [ "${#expected}" -ne 64 ]; then
  echo "pentect: release checksum is invalid" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$temp_dir/$asset" | awk '{ print tolower($1) }')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$temp_dir/$asset" | awk '{ print tolower($1) }')
else
  echo "pentect: sha256sum or shasum is required" >&2
  exit 1
fi
if [ "$actual" != "$expected" ]; then
  echo "pentect: release checksum mismatch" >&2
  exit 1
fi

printf '[3/4] Installing binary...\n'
mkdir -p "$install_dir"
staged="$install_dir/.pentect.install.$$"
cp "$temp_dir/$asset" "$staged"
chmod 0755 "$staged"
mv -f "$staged" "$destination"
printf '%s\n' '{"version":1,"manager":"pentect","path_added":false}' > "$marker"

case ":${PATH:-}:" in
  *":$install_dir:"*) path_status="already on PATH" ;;
  *) path_status="add $install_dir to PATH" ;;
esac
printf '[4/4] PATH: %s\n\n' "$path_status"
printf 'Installed Pentect %s\n' "$release_tag"
printf 'Next: pentect doctor\n'
