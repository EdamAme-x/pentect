#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: wait_for_automation_pr.sh PULL BRANCH TITLE BODY" >&2
  exit 2
fi

pull=$1
branch=$2
title=$3
body=$4
attempts=${PENTECT_AUTOMATION_PR_WAIT_ATTEMPTS:-240}
delay=${PENTECT_AUTOMATION_PR_WAIT_SECONDS:-10}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
propose=${PENTECT_PROPOSE_AUTOMATION_PR:-$script_dir/propose_automation_pr.sh}

for attempt in $(seq 1 "$attempts"); do
  details=$(gh pr view "$pull" --repo "$GITHUB_REPOSITORY" \
    --json state,mergeStateStatus)
  state=$(printf '%s\n' "$details" | jq -r .state)
  case "$state" in
    MERGED) printf '%s\n' "$pull"; exit 0 ;;
    CLOSED) echo "automation pull request closed without merging" >&2; exit 1 ;;
  esac
  if [ "$(printf '%s\n' "$details" | jq -r .mergeStateStatus)" = BEHIND ]; then
    echo "automation pull request fell behind main; revalidating a new head" >&2
    # Auto-merge was authorized for the previously validated SHA. Disable it
    # before replacing that head, then let propose_automation_pr.sh validate
    # and authorize the exact rebased SHA.
    gh pr merge "$pull" --repo "$GITHUB_REPOSITORY" --disable-auto
    git fetch origin main --no-tags
    git rebase origin/main
    pull=$(sh "$propose" "$branch" "$title" "$body")
  fi
  sleep "$delay"
done

echo "automation pull request did not merge after $attempts checks" >&2
exit 1
