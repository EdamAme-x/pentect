#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: dispatch_package_site.sh REPOSITORY TAG RELEASE_SHA MAIN_SHA" >&2
  exit 2
fi

repository=$1
tag=$2
release_sha=$3
main_sha=$4
correlation="release-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
discover_attempts=${PENTECT_PACKAGE_RUN_DISCOVERY_ATTEMPTS:-30}
poll_attempts=${PENTECT_PACKAGE_RUN_POLL_ATTEMPTS:-300}
discover_delay=${PENTECT_PACKAGE_RUN_DISCOVERY_DELAY:-2}
poll_delay=${PENTECT_PACKAGE_RUN_POLL_DELAY:-5}
title="Publish packages / sync-$correlation"

for value in "$discover_attempts" "$poll_attempts"; do
  case "$value" in
    ''|*[!0-9]*|0) echo "package run attempt limits must be positive integers" >&2; exit 2 ;;
  esac
done
for value in "$discover_delay" "$poll_delay"; do
  case "$value" in
    ''|*[!0-9]*) echo "package run delays must be non-negative integers" >&2; exit 2 ;;
  esac
done

current_main=$(gh api "repos/$repository/commits/main" --jq .sha)
if [ "$main_sha" = "$release_sha" ]; then
  echo "package metadata did not advance main beyond the release commit" >&2
  exit 1
fi
if [ "$current_main" != "$main_sha" ]; then
  echo "main advanced after the package metadata merge; refusing an uncorrelated APT sync" >&2
  exit 1
fi

runs=$(gh api \
  "repos/$repository/actions/workflows/packages.yml/runs?branch=main&per_page=100" \
  --jq '.workflow_runs[] | [.id, .head_sha] | @tsv')
existing=$(printf '%s\n' "$runs" \
  | awk -F '\t' -v sha="$main_sha" '$2 == sha { print $1; exit }')
if [ -n "$existing" ]; then
  echo "packages workflow already ran for the intended main commit; refusing a duplicate Pages deployment" >&2
  exit 1
fi

gh workflow run packages.yml \
  --repo "$repository" \
  --ref main \
  -f tag="$tag" \
  -f correlation="$correlation"

run_id=
run_sha=
attempt=1
while [ "$attempt" -le "$discover_attempts" ]; do
  runs=$(gh api \
    "repos/$repository/actions/workflows/packages.yml/runs?event=workflow_dispatch&per_page=50" \
    --jq '.workflow_runs[] | [.id, .display_title, .head_sha] | @tsv')
  match=$(printf '%s\n' "$runs" \
    | awk -F '\t' -v title="$title" '$2 == title { print $1 "|" $3; exit }')
  if [ -n "$match" ]; then
    run_id=${match%%|*}
    run_sha=${match#*|}
    break
  fi
  sleep "$discover_delay"
  attempt=$((attempt + 1))
done
if [ -z "$run_id" ]; then
  echo "could not locate the correlated package publication run" >&2
  exit 1
fi
if [ "$run_sha" != "$main_sha" ]; then
  echo "correlated package publication run used an unexpected main commit" >&2
  exit 1
fi

echo "APT site sync: $GITHUB_SERVER_URL/$repository/actions/runs/$run_id"
attempt=1
while [ "$attempt" -le "$poll_attempts" ]; do
  state=$(gh api "repos/$repository/actions/runs/$run_id" \
    --jq '[.status, (.conclusion // "")] | join("|")')
  status=${state%%|*}
  conclusion=${state#*|}
  if [ "$status" = completed ]; then
    if [ "$conclusion" = success ]; then
      exit 0
    fi
    echo "package publication run completed with conclusion: $conclusion" >&2
    exit 1
  fi
  sleep "$poll_delay"
  attempt=$((attempt + 1))
done

echo "timed out waiting for the package publication run" >&2
exit 1
