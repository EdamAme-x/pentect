#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: propose_automation_pr.sh BRANCH TITLE BODY" >&2
  exit 2
fi

branch=$1
title=$2
body=$3
case "$branch" in
  automation/*) ;;
  *) echo "automation branch must start with automation/" >&2; exit 2 ;;
esac
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

remote_sha=$(git ls-remote origin "refs/heads/$branch" | awk 'NR == 1 { print $1 }')
git config --local credential.helper '!f() { test "$1" = get && echo username=x-access-token && echo "password=$GH_TOKEN"; }; f'
cleanup() {
  git config --local --unset-all credential.helper >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

if [ -n "$remote_sha" ]; then
  git push --force-with-lease="refs/heads/$branch:$remote_sha" origin "HEAD:refs/heads/$branch"
else
  git push origin "HEAD:refs/heads/$branch"
fi

pull=$(gh pr list --repo "$GITHUB_REPOSITORY" --state open --head "$branch" --json url --jq '.[0].url // empty')
if [ -z "$pull" ]; then
  pull=$(gh pr create \
    --repo "$GITHUB_REPOSITORY" \
    --base main \
    --head "$branch" \
    --title "$title" \
    --body "$body")
fi

# Events created with GITHUB_TOKEN do not recursively start pull_request
# workflows. Explicitly dispatch CI against the exact automation commit so the
# protected branch still receives every required check.
gh workflow run ci.yml --repo "$GITHUB_REPOSITORY" --ref "$branch" >&2
gh pr merge "$pull" --repo "$GITHUB_REPOSITORY" --auto --merge --delete-branch \
  --match-head-commit "$(git rev-parse HEAD)" >&2
printf '%s\n' "$pull"
