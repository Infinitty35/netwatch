#!/usr/bin/env bash
# The release workflow's first job: refuse a tag that is not a finished,
# CI-tested release.
#
#   scripts/release-guard.sh vX.Y.Z
#
# Run from a checkout of the tag. Fails unless the tag is "v" plus Cargo.toml's
# version and CHANGELOG.md has a section for that version. Then it waits for
# every ci.yml run on the checked-out commit to finish, and fails on any
# conclusion other than success, or if no CI run appears at all. The tag and
# its commit are usually pushed together, so CI may not have started yet.
#
# Needs cargo, jq and a gh that can read the repository's runs. The waits are
# in seconds: GUARD_POLL between checks (30), GUARD_FIRST_RUN for a CI run to
# appear (300) and GUARD_TIMEOUT for every run to finish (1800). The tests in
# tests/release.rs shorten them and put a fake gh on PATH.
set -euo pipefail

TAG="${1:?usage: release-guard.sh vX.Y.Z}"
REPO="${GITHUB_REPOSITORY:-matthart1983/netwatch}"
POLL="${GUARD_POLL:-30}"
FIRST_RUN="${GUARD_FIRST_RUN:-300}"
TIMEOUT="${GUARD_TIMEOUT:-1800}"

# `::error::` marks the line as the failure in the Actions log.
die() { echo "::error::$*"; exit 1; }

version=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
[ "v${version}" = "${TAG}" ] || die "${TAG} is not the crate's version: Cargo.toml says ${version}"
awk -v h="## [${version}]" 'index($0, h) == 1 { found = 1 } END { exit !found }' CHANGELOG.md ||
    die "CHANGELOG.md has no '## [${version}]' heading"

# The commit the tag names. Not $GITHUB_SHA: on a manual dispatch that is the
# head of the branch the workflow was started from.
sha=$(git rev-parse HEAD)
start=$(date +%s)
while :; do
    runs=$(gh run list -R "${REPO}" --workflow ci.yml --commit "${sha}" \
        --json databaseId,conclusion,status,event,url)
    total=$(jq length <<< "${runs}")
    running=$(jq '[.[] | select(.status != "completed")] | length' <<< "${runs}")
    failed=$(jq '[.[] | select(.status == "completed" and .conclusion != "success")] | length' <<< "${runs}")
    elapsed=$(( $(date +%s) - start ))
    if [ "${failed}" -gt 0 ]; then
        jq -r '.[] | "\(.status) \(.conclusion) \(.event) \(.url)"' <<< "${runs}"
        # A later run on the commit does not clear a failed one, since every
        # finished run has to pass. Re-running the failed run replaces its
        # result.
        jq -r '.[] | select(.status == "completed" and .conclusion != "success")
            | "  gh run rerun \(.databaseId) --failed"' <<< "${runs}"
        die "CI did not pass on ${sha}. Fix it and tag the fix; or, if the failure was flaky, re-run the failed run with the command above, and then this workflow."
    fi
    if [ "${total}" -gt 0 ] && [ "${running}" -eq 0 ]; then
        jq -r '.[] | "\(.conclusion) \(.event) \(.url)"' <<< "${runs}"
        break
    fi
    if [ "${total}" -eq 0 ] && [ "${elapsed}" -ge "${FIRST_RUN}" ]; then
        die "No CI run for ${sha}. ci.yml runs by itself only on the head of a push to main and on pull requests into it; for any other commit, run 'gh workflow run ci.yml --ref ${TAG}', then re-run this workflow once it passes."
    fi
    if [ "${elapsed}" -ge "${TIMEOUT}" ]; then
        die "CI on ${sha} was still running after ${TIMEOUT} seconds"
    fi
    echo "Waiting on CI for ${sha}: ${total} run(s), ${running} still running"
    sleep "${POLL}"
done
