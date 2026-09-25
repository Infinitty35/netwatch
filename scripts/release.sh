#!/usr/bin/env bash
# Make a release commit and its tag, locally.
#
#   scripts/release.sh 0.32.4 "what this release is, for the commit subject"
#
# Bumps Cargo.toml and Cargo.lock, the RPM spec's Version and %changelog, and
# renames CHANGELOG.md's `## [Unreleased]` to `## [X.Y.Z] - <today>`. Then it
# runs `cargo test`, commits "release: netwatch vX.Y.Z — <summary>" and makes
# the annotated tag. It pushes nothing; the push commands are printed at the
# end. The release workflow refuses a tag that disagrees with Cargo.toml or
# has no CHANGELOG heading, and waits for CI to pass on the tagged commit.
#
# Refuses to start on a dirty tree, a detached HEAD, a branch other than
# `main` or `release/X.Y.Z`, a branch behind its remote, a tag that already
# exists, a version not above the current one, or an empty `[Unreleased]`.
#
# package.nix is not touched: it is still at 0.26.1, and should be bumped by
# someone who can check that it builds with nix.
set -euo pipefail

usage="usage: release.sh X.Y.Z \"summary\""
VERSION="${1:?${usage}}"
SUMMARY="${2:?${usage}}"
TAG="v${VERSION}"
SPEC="packaging/rpm/netwatch.spec"

die() { echo "release.sh: $*" >&2; exit 1; }

# rewrite FILE AWK-PROGRAM: replace FILE with the program's output. Not
# `sed -i`, which takes different arguments on macOS.
rewrite() {
    awk "$2" "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

# newer A B: is X.Y.Z version A above B? `sort -V` is GNU-only.
newer() {
    local IFS=.
    local -a a=($1) b=($2)
    local i
    for i in 0 1 2; do
        [ "${a[i]}" -gt "${b[i]}" ] && return 0
        [ "${a[i]}" -lt "${b[i]}" ] && return 1
    done
    return 1
}

[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "${VERSION} is not X.Y.Z (no leading v; pre-releases are tagged by hand)"

root=$(git rev-parse --show-toplevel)
cd "${root}"

branch=$(git symbolic-ref --quiet --short HEAD) ||
    die "HEAD is detached; check out main or release/${VERSION}"
case "${branch}" in
    main | "release/${VERSION}") ;;
    *) die "on ${branch}; a ${VERSION} release is made on main or release/${VERSION}" ;;
esac

if [ -n "$(git status --porcelain)" ]; then
    git status --short >&2
    die "the working tree is not clean; commit or remove the changes above first"
fi

# Behind its remote, the release commit could not be pushed without a merge,
# and the tag would name a commit that never reaches the branch. Only checked
# against a remote branch of the same name: a release branch that tracks
# origin/main is expected to be behind it.
if upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null) &&
    [ "${upstream#*/}" = "${branch}" ]; then
    git fetch --quiet "${upstream%%/*}" "${branch}" || die "could not fetch ${upstream}"
    behind=$(git rev-list --count "HEAD..${upstream}")
    [ "${behind}" -eq 0 ] || die "${branch} is ${behind} commit(s) behind ${upstream}; pull first"
fi

git rev-parse --quiet --verify "refs/tags/${TAG}" > /dev/null && die "${TAG} already exists"

current=$(awk -F'"' '/^\[/ { pkg = ($0 == "[package]") } pkg && /^version *=/ { print $2; exit }' Cargo.toml)
[ -n "${current}" ] || die "no version in Cargo.toml's [package]"
# A pre-release (0.33.0-rc.1) may be followed by its own X.Y.Z.
core="${current%%-*}"
if ! newer "${VERSION}" "${core}" && ! { [ "${VERSION}" = "${core}" ] && [ "${current}" != "${core}" ]; }; then
    die "${VERSION} is not above the current version, ${current}"
fi

grep -q "^## \[${VERSION}\]" CHANGELOG.md && die "CHANGELOG.md already has a ${VERSION} section"
unreleased=$(awk '/^## \[Unreleased\][[:space:]]*$/ { on = 1; next }
    on && /^## \[/ { exit }
    on && NF { n++ }
    END { print n + 0 }' CHANGELOG.md)
[ "${unreleased}" -gt 0 ] ||
    die "CHANGELOG.md has no '## [Unreleased]' section, or it is empty; write the release notes there first"

echo "==> ${current} -> ${VERSION} on ${branch}"

# Handed to awk through the environment: `awk -v` would read backslashes in
# the summary as escapes.
TODAY=$(date +%F)
RPM_HEAD="* $(LC_ALL=C date '+%a %b %d %Y') $(git config user.name) <$(git config user.email)> - ${VERSION}-1"
export V="${VERSION}" SUMMARY TODAY RPM_HEAD

rewrite Cargo.toml '/^\[/ { pkg = ($0 == "[package]") }
    pkg && !done && /^version *=/ { $0 = "version = \"" ENVIRON["V"] "\""; done = 1 }
    { print }'
rewrite "${SPEC}" '/^Version:/ { sub(/[^[:space:]]+$/, ENVIRON["V"]) }
    { print }
    /^%changelog/ { print ENVIRON["RPM_HEAD"]; print "- " ENVIRON["SUMMARY"]; print "" }'
rewrite CHANGELOG.md '!done && /^## \[Unreleased\][[:space:]]*$/ {
        $0 = "## [" ENVIRON["V"] "] - " ENVIRON["TODAY"]; done = 1 }
    { print }'

# --workspace rewrites only this crate's own entry in the lockfile.
cargo update --workspace --quiet
grep -A1 '^name = "netwatch-tui"$' Cargo.lock | grep -qx "version = \"${VERSION}\"" ||
    die "Cargo.lock did not take ${VERSION}"

echo "==> cargo test"
cargo test ||
    die "cargo test failed; the version edits are left uncommitted (git checkout -- . discards them)"

git add Cargo.toml Cargo.lock "${SPEC}" CHANGELOG.md
git commit --quiet -m "release: netwatch ${TAG} — ${SUMMARY}"
git tag -a "${TAG}" -m "netwatch ${TAG}"

echo
echo "Committed and tagged ${TAG} locally. Nothing has been pushed."
if [ "${branch}" = main ]; then
    echo "  git push --atomic origin main ${TAG}"
else
    # ci.yml runs on pushes to main and pull requests into it, so a release
    # branch has to ask for CI, or the release workflow finds no run to wait on.
    echo "  git push origin ${branch}"
    echo "  gh workflow run ci.yml --ref ${branch}"
    echo "  git push origin ${TAG}"
fi
