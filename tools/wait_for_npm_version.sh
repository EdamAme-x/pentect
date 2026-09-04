#!/bin/sh
set -eu
package=${1:?usage: wait_for_npm_version.sh PACKAGE VERSION [ATTEMPTS] [DELAY_SECONDS]}
version=${2:?usage: wait_for_npm_version.sh PACKAGE VERSION [ATTEMPTS] [DELAY_SECONDS]}
attempts=${3:-30}
delay=${4:-5}
case "$attempts" in ''|*[!0-9]*|0) echo "attempts must be a positive integer" >&2; exit 2;; esac
case "$delay" in ''|*[!0-9]*) echo "delay must be a non-negative integer" >&2; exit 2;; esac
attempt=1
error_file=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pentect-npm-view.XXXXXX")
trap 'rm -f "$error_file"' EXIT HUP INT TERM
while test "$attempt" -le "$attempts"; do
  : >"$error_file"
  if observed=$(npm view "$package@$version" version \
      --prefer-online \
      --registry=https://registry.npmjs.org \
      --fetch-retries=0 \
      --fetch-timeout=5000 2>"$error_file"); then
    test "$observed" = "$version" || { echo "npm returned unexpected version '$observed' for $package@$version" >&2; exit 1; }
    echo "$package@$version is visible in the npm registry"
    exit 0
  fi
  error=$(cat "$error_file")
  if ! printf '%s\n' "$error" | grep -Eq '(^|[[:space:]])E404([[:space:]]|$)|404 Not Found'; then
    printf '%s\n' "$error" >&2
    echo "npm registry lookup failed permanently for $package@$version" >&2
    exit 1
  fi
  if test "$attempt" -eq "$attempts"; then
    echo "$package@$version is still not visible after $attempts attempts" >&2
    exit 4
  fi
  sleep "$delay"
  attempt=$((attempt + 1))
done
