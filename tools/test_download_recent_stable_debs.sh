#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/debs"

cat > "$temporary/bin/gh" <<'EOF'
#!/bin/sh
set -eu
case "$1 $2" in
  'api --paginate')
    printf '%s\n' v5 v4 v3 v2 v1
    ;;
  'release view')
    [ "$3" = v4 ] && exit 0
    printf '%s\n' pentect_1.0.0_amd64.deb pentect_1.0.0_arm64.deb
    ;;
  'release download')
    tag=$3
    shift 3
    destination=
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --dir ]; then
        destination=$2
        break
      fi
      shift
    done
    : "${destination:?missing download directory}"
    : > "$destination/pentect_${tag#v}_amd64.deb"
    : > "$destination/pentect_${tag#v}_arm64.deb"
    ;;
  *)
    echo "unexpected gh invocation: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "$temporary/bin/gh"

PATH="$temporary/bin:$PATH" GITHUB_REPOSITORY=owner/repo \
  sh "$root/tools/download_recent_stable_debs.sh" "$temporary/debs" 3

actual=$(find "$temporary/debs" -type f -name '*.deb' -printf '%f\n' | sort)
expected=$(printf '%s\n' \
  pentect_2_amd64.deb pentect_2_arm64.deb \
  pentect_3_amd64.deb pentect_3_arm64.deb \
  pentect_5_amd64.deb pentect_5_arm64.deb | sort)
[ "$actual" = "$expected" ]
