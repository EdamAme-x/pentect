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

# Pushes authenticated with GITHUB_TOKEN do not trigger pull_request workflows.
# Validate the exact automation commit through workflow_dispatch, then publish
# the three required commit statuses only after both workflows succeed.
head=$(git rev-parse HEAD)
latest_run() {
  gh run list \
    --repo "$GITHUB_REPOSITORY" \
    --workflow "$1" \
    --branch "$branch" \
    --event workflow_dispatch \
    --limit 10 \
    --json databaseId,headSha \
    --jq ".[] | select(.headSha == \"$head\") | .databaseId" \
    | head -n 1
}

previous_ci=$(latest_run ci.yml)
previous_nix=$(latest_run nix.yml)
gh workflow run ci.yml --repo "$GITHUB_REPOSITORY" --ref "$branch" >&2
gh workflow run nix.yml --repo "$GITHUB_REPOSITORY" --ref "$branch" >&2
aur_state=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/aur.yml" --jq .state)
if [ "$aur_state" = active ]; then
  gh workflow run aur.yml --repo "$GITHUB_REPOSITORY" --ref "$branch" >&2
else
  echo "AUR workflow is $aur_state; skipping automation PR validation" >&2
fi

new_run() {
  workflow=$1
  previous=$2
  for attempt in $(seq 1 30); do
    run_id=$(latest_run "$workflow")
    if [ -n "$run_id" ] && [ "$run_id" != "$previous" ]; then
      printf '%s\n' "$run_id"
      return 0
    fi
    sleep 2
  done
  echo "could not find dispatched $workflow run for $head" >&2
  return 1
}

ci_run=$(new_run ci.yml "$previous_ci")
nix_run=$(new_run nix.yml "$previous_nix")
gh run watch "$ci_run" --repo "$GITHUB_REPOSITORY" --exit-status >&2
gh run watch "$nix_run" --repo "$GITHUB_REPOSITORY" --exit-status >&2

ci_url="https://github.com/$GITHUB_REPOSITORY/actions/runs/$ci_run"
for context in \
  test \
  'Native OCR (windows-latest)' \
  'Native OCR (macos-latest)'
do
  gh api --method POST "repos/$GITHUB_REPOSITORY/statuses/$head" \
    -f state=success \
    -f context="$context" \
    -f description='Validated by the automation PR CI workflow' \
    -f target_url="$ci_url" >/dev/null
done

gh pr merge "$pull" --repo "$GITHUB_REPOSITORY" --auto --merge --delete-branch \
  --match-head-commit "$head" >&2
printf '%s\n' "$pull"
