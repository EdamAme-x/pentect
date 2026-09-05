#!/bin/sh
set -eu

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
mkdir "$root/bin" "$root/out"
cat > "$root/bin/gh" <<'EOF'
#!/bin/sh
set -eu
if [ "$1 $2" = "api --paginate" ]; then
  printf '%s\n' v1.2.3 v1.2.2 v1.2.1
  exit
fi
if [ "$1 $2" = "release view" ]; then
  tag=$3
  reported_tag=$tag
  [ "${FAKE_MODE:-ok}" = wrong-tag ] && reported_tag=v9.9.9
  case "${FAKE_MODE:-ok}:$tag" in
    prerelease:v1.2.3) pre=true ;; *) pre=false ;;
  esac
  case "${FAKE_MODE:-ok}:$tag" in
    draft:v1.2.3) draft=true ;; *) draft=false ;;
  esac
  assets='[{"name":"pentect_'"${tag#v}"'_amd64.deb"},{"name":"pentect_'"${tag#v}"'_arm64.deb"}]'
  [ "${FAKE_MODE:-ok}" = missing-arm64 ] && assets='[{"name":"pentect_'"${tag#v}"'_amd64.deb"}]'
  printf '{"tagName":"%s","isDraft":%s,"isPrerelease":%s,"assets":%s}\n' "$reported_tag" "$draft" "$pre" "$assets"
  exit
fi
if [ "$1 $2" = "release download" ]; then
  tag=$3; shift 3; asset=; directory=
  while [ "$#" -gt 0 ]; do
    case "$1" in --pattern) asset=$2; shift 2 ;; --dir) directory=$2; shift 2 ;; *) shift ;; esac
  done
  : > "$directory/$asset"
  exit
fi
exit 2
EOF
cat > "$root/bin/dpkg-deb" <<'EOF'
#!/bin/sh
set -eu
file=$2; field=$3; name=${file##*/}; value=${name#pentect_}; version=${value%_*}; architecture=${value##*_}; architecture=${architecture%.deb}
[ "${FAKE_MODE:-ok}" = wrong-arch ] && architecture=all
[ "${FAKE_MODE:-ok}" = wrong-version ] && version=9.9.9
case "$field" in Package) [ "${FAKE_MODE:-ok}" = wrong-package ] && echo other || echo pentect ;; Version) echo "$version" ;; Architecture) echo "$architecture" ;; *) exit 2 ;; esac
EOF
chmod +x "$root/bin/gh" "$root/bin/dpkg-deb"
export PATH="$root/bin:$PATH" GITHUB_REPOSITORY=EdamAme-x/pentect

sh tools/prepare_stable_debs.sh "$root/out" v1.2.3 3
test "$(find "$root/out" -name '*.deb' | wc -l)" -eq 6

for case in 'bad-tag:v1.2:ok' 'wrong-tag:v1.2.3:wrong-tag' 'draft:v1.2.3:draft' 'prerelease:v1.2.3:prerelease' 'missing:v1.2.3:missing-arm64' 'wrong-package:v1.2.3:wrong-package' 'wrong-version:v1.2.3:wrong-version' 'wrong-arch:v1.2.3:wrong-arch'; do
  name=${case%%:*}; rest=${case#*:}; tag=${rest%%:*}; FAKE_MODE=${rest#*:}; export FAKE_MODE
  rm -rf "$root/out"; mkdir "$root/out"
  if sh tools/prepare_stable_debs.sh "$root/out" "$tag" 3 >/dev/null 2>&1; then
    echo "$name unexpectedly succeeded" >&2
    exit 1
  fi
done

workflow=.github/workflows/packages.yml
grep -Fq 'run-name: Publish packages / sync-${{ inputs.correlation || github.run_id }}' "$workflow"
grep -Fq 'contents: read' "$workflow"
grep -Fq 'sh tools/prepare_stable_debs.sh debs "$TAG" 3' "$workflow"
if grep -Eq 'release upload|--clobber|package_deb\.sh' "$workflow"; then
  echo "packages workflow may not rebuild or overwrite stable assets" >&2
  exit 1
fi

echo "prepare_stable_debs tests passed"
