#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! $1 =~ ^pentect-(bin|git)$ ]]; then
  echo 'usage: publish-aur.sh pentect-bin|pentect-git' >&2
  exit 2
fi
: "${AUR_SSH_PRIVATE_KEY:?AUR_SSH_PRIVATE_KEY is required}"

package=$1
source_directory="$GITHUB_WORKSPACE/packaging/aur/$package"
key_file="$RUNNER_TEMP/aur-key"
host_scan="$RUNNER_TEMP/aur-host-scan"
known_hosts="$RUNNER_TEMP/aur-known-hosts"
remote_directory="$RUNNER_TEMP/aur-$package"

umask 077
printf '%s\n' "$AUR_SSH_PRIVATE_KEY" > "$key_file"
ssh-keyscan -H -t ed25519 aur.archlinux.org > "$host_scan"
fingerprint=$(ssh-keygen -l -f "$host_scan" | awk 'NR == 1 { print $2 }')
if [[ "$fingerprint" != 'SHA256:RFzBCUItH9LZS0cKB5UE6ceAYhBD5C8GeOBip8Z11+4' ]]; then
  echo "unexpected AUR SSH host key fingerprint: $fingerprint" >&2
  exit 1
fi
mv "$host_scan" "$known_hosts"

export GIT_SSH_COMMAND="ssh -i $key_file -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts"
git -c init.defaultBranch=master clone "ssh://aur@aur.archlinux.org/$package.git" "$remote_directory"
cd "$remote_directory"
git rm -r --ignore-unmatch .
install -m 0644 "$source_directory/PKGBUILD" PKGBUILD
install -m 0644 "$source_directory/.SRCINFO" .SRCINFO
install -m 0644 "$source_directory/LICENSE" LICENSE
git add --all

if git diff --cached --quiet; then
  echo "$package is already synchronized"
  exit 0
fi

git config user.name EdamAmex
git config user.email 121654029+EdamAme-x@users.noreply.github.com
git commit -m "Update $package from pentect ${GITHUB_SHA:0:12}"
git push origin HEAD:master
