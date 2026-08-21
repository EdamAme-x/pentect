#!/bin/sh
set -eu

if test "$#" -ne 1; then
  echo "usage: install_client_smoke.sh ROOT" >&2
  exit 2
fi

root=$1
case "$root" in
  /*) ;;
  *) echo "client smoke root must be absolute" >&2; exit 2 ;;
esac

home="$root/home"
bin="$root/bin"
downloads="$root/downloads"
mkdir -p "$home" "$bin" "$downloads"
export HOME="$home"
export XDG_CONFIG_HOME="$home/.config"
export XDG_DATA_HOME="$home/.local/share"
export UV_TOOL_DIR="$root/uv-tools"
export UV_TOOL_BIN_DIR="$bin"
export UV_LINK_MODE=copy
export CI=true

latest=${PENTECT_CLIENT_SMOKE_LATEST:-0}
if test "$latest" = 1; then
  aider_spec=aider-chat
  goose_version=
  junie_version=
  roo_extension=RooVeterinaryInc.roo-cline
  zed_version=latest
else
  aider_spec=aider-chat==0.86.2
  goose_version=v1.46.0
  junie_version=2777.8
  roo_extension=RooVeterinaryInc.roo-cline@3.54.0
  zed_version=1.16.1
fi

download() {
  curl --fail --silent --show-error --location \
    --retry 3 --retry-all-errors --connect-timeout 20 \
    "$1" --output "$2"
}

echo "Installing Aider..."
uv tool install --python 3.12 "$aider_spec"

echo "Installing Antigravity CLI..."
download https://antigravity.google/cli/install.sh "$downloads/antigravity.sh"
bash "$downloads/antigravity.sh" --dir "$bin"

echo "Installing Goose CLI..."
download \
  https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh \
  "$downloads/goose.sh"
if test -n "$goose_version"; then
  CONFIGURE=false GOOSE_BIN_DIR="$bin" GOOSE_VERSION="$goose_version" bash "$downloads/goose.sh"
else
  CONFIGURE=false GOOSE_BIN_DIR="$bin" bash "$downloads/goose.sh"
fi

echo "Installing Junie CLI..."
download https://junie.jetbrains.com/install.sh "$downloads/junie.sh"
if test -n "$junie_version"; then
  JUNIE_VERSION="$junie_version" bash "$downloads/junie.sh"
else
  bash "$downloads/junie.sh"
fi

echo "Installing Roo Code extension..."
if ! command -v code >/dev/null 2>&1; then
  echo "Installing VS Code CLI..."
  download \
    'https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64' \
    "$downloads/code.deb"
  sudo apt-get install -y "$downloads/code.deb"
fi
code --install-extension "$roo_extension" --force

echo "Installing Zed..."
download https://zed.dev/install.sh "$downloads/zed.sh"
ZED_VERSION="$zed_version" sh "$downloads/zed.sh"

for executable in \
  "$bin/aider" \
  "$bin/agy" \
  "$bin/goose" \
  "$home/.local/bin/junie" \
  "$home/.local/bin/zed"
do
  test -x "$executable" || {
    echo "client installer did not produce $executable" >&2
    exit 1
  }
done
code --list-extensions | grep -Fixq RooVeterinaryInc.roo-cline
