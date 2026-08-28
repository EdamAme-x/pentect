#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: download_recent_stable_debs.sh OUTPUT_DIR RELEASE_COUNT" >&2
  exit 2
fi

output_dir=$1
release_count=$2
case "$release_count" in
  ''|*[!0-9]*|0) echo "RELEASE_COUNT must be a positive integer" >&2; exit 2 ;;
esac

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
command -v gh >/dev/null 2>&1 || { echo "gh is required" >&2; exit 2; }

mkdir -p "$output_dir"
tags_file=$(mktemp)
trap 'rm -f "$tags_file"' EXIT HUP INT TERM
gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
  --jq '.[] | select(.draft == false and .prerelease == false) | .tag_name' > "$tags_file"

retained=0
while IFS= read -r tag; do
  if gh release view "$tag" --repo "$GITHUB_REPOSITORY" \
    --json assets --jq '.assets[].name' | grep -Eq '^pentect_.*\.deb$'; then
    gh release download "$tag" --repo "$GITHUB_REPOSITORY" \
      --pattern 'pentect_*.deb' --dir "$output_dir" --skip-existing
    retained=$((retained + 1))
    [ "$retained" -ge "$release_count" ] && break
  fi
done < "$tags_file"

echo "Retained Debian packages from $retained stable release(s)."
