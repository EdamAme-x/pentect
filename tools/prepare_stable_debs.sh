#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: prepare_stable_debs.sh OUTPUT_DIR SELECTED_TAG RELEASE_COUNT" >&2
  exit 2
fi

output_dir=$1
selected_tag=$2
release_count=$3
case "$release_count" in
  ''|*[!0-9]*|0) echo "RELEASE_COUNT must be a positive integer" >&2; exit 2 ;;
esac

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
command -v gh >/dev/null 2>&1 || { echo "gh is required" >&2; exit 2; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

validate_tag() {
  printf '%s\n' "$1" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
    echo "invalid stable release tag: $1" >&2
    exit 2
  }
}
validate_tag "$selected_tag"

mkdir -p "$output_dir"
test -z "$(find "$output_dir" -mindepth 1 -print -quit)" || {
  echo "OUTPUT_DIR must be empty" >&2
  exit 2
}
tags_file=$(mktemp)
trap 'rm -f "$tags_file"' EXIT HUP INT TERM

selected_metadata=$(gh release view "$selected_tag" --repo "$GITHUB_REPOSITORY" \
  --json tagName,isDraft,isPrerelease,assets)
test "$(printf '%s' "$selected_metadata" | jq -r .tagName)" = "$selected_tag"
test "$(printf '%s' "$selected_metadata" | jq -r .isDraft)" = false
test "$(printf '%s' "$selected_metadata" | jq -r .isPrerelease)" = false

gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
  --jq '.[] | select(.draft == false and .prerelease == false) | .tag_name' > "$tags_file"

verify_release() {
  tag=$1
  metadata=$2
  release_version=${tag#v}
  test "$(printf '%s' "$metadata" | jq -r .tagName)" = "$tag"
  test "$(printf '%s' "$metadata" | jq -r .isDraft)" = false
  test "$(printf '%s' "$metadata" | jq -r .isPrerelease)" = false
  for architecture in amd64 arm64; do
    asset="pentect_${release_version}_${architecture}.deb"
    test "$(printf '%s' "$metadata" | jq --arg asset "$asset" '[.assets[] | select(.name == $asset)] | length')" = 1
    gh release download "$tag" --repo "$GITHUB_REPOSITORY" \
      --pattern "$asset" --dir "$output_dir" --skip-existing
    package_path=$output_dir/$asset
    test -f "$package_path"
    test "$(dpkg-deb -f "$package_path" Package)" = pentect
    test "$(dpkg-deb -f "$package_path" Version)" = "$release_version"
    test "$(dpkg-deb -f "$package_path" Architecture)" = "$architecture"
  done
}

verify_release "$selected_tag" "$selected_metadata"
retained=1
while [ "$retained" -lt "$release_count" ] && IFS= read -r tag; do
  [ "$tag" = "$selected_tag" ] && continue
  if ! printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    continue
  fi
  metadata=$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" \
    --json tagName,isDraft,isPrerelease,assets)
  test "$(printf '%s' "$metadata" | jq -r .tagName)" = "$tag"
  test "$(printf '%s' "$metadata" | jq -r .isDraft)" = false
  test "$(printf '%s' "$metadata" | jq -r .isPrerelease)" = false
  release_version=${tag#v}
  amd64="pentect_${release_version}_amd64.deb"
  arm64="pentect_${release_version}_arm64.deb"
  [ "$(printf '%s' "$metadata" | jq --arg asset "$amd64" '[.assets[] | select(.name == $asset)] | length')" = 1 ] || continue
  [ "$(printf '%s' "$metadata" | jq --arg asset "$arm64" '[.assets[] | select(.name == $asset)] | length')" = 1 ] || continue
  verify_release "$tag" "$metadata"
  retained=$((retained + 1))
done < "$tags_file"
echo "Prepared verified Debian packages from $retained stable release(s)."
