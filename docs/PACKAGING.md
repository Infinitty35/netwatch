# Packaging

Where netwatch is distributed, what produces each package, and what to do by
hand when a release goes out.

## The channels

| Channel | Built by | Updated by | Source |
|---|---|---|---|
| homebrew-core (`brew install netwatch`) | Homebrew | Homebrew autobump, within hours of a tag | the tag's source archive |
| crates.io (`netwatch-tui`) | `publish` job in `release.yml` | every tag | this repository |
| GitHub release binaries | `build` job | every tag | musl-static (Linux), native (macOS/Windows) |
| GitHub release `.deb` / `.rpm` | `build` job, `cargo-deb` + `cargo-generate-rpm` | every tag | the same static binary |
| Fedora COPR | COPR builders from `packaging/rpm/netwatch.spec` | a tag, via webhook | built from source against system libpcap |
| Scoop (Windows) | ScoopInstaller/Main | the bucket's autoupdate bot | GitHub release |
| AUR `netwatch-tui`, `netwatch-tui-bin` | community maintainers | community | — |
| nixpkgs | community maintainer | community | — |
| `matthart1983/homebrew-tap` | — | **deprecated**, no longer updated | superseded by homebrew-core |

Only the first five are ours. The others are maintained by other people; if
they lag, the fix is a polite issue, not a commit here.

## The two RPMs

They are different on purpose.

- **`netwatch-<version>-1.<arch>.rpm` on the release page** repackages the
  musl-static binary. `auto-req = "no"`, no dependencies, installs on anything
  with rpm. Produced by `cargo generate-rpm` from the `[package.metadata.generate-rpm]`
  table in `Cargo.toml`.
- **The COPR package** is built from source against the system libpcap by
  `packaging/rpm/netwatch.spec`, so it has a normal `Requires: libpcap` and
  behaves like any other Fedora package.

`.deb` follows the first model only; `[package.metadata.deb]` in `Cargo.toml`
drives it, with maintainer scripts in `packaging/debian/`.

## Capabilities

No package grants capabilities. Capture needs `CAP_NET_RAW` (and `CAP_BPF` /
`CAP_PERFMON` for eBPF attribution), and a package that hands those to a binary
without asking takes a decision that belongs to the administrator. Every
post-install prints the `setcap` line instead, and CI fails the release if an
installed package ever comes with capabilities already applied.

## Per-release checklist

Most of it is automatic. By hand:

1. Bump `version` in `Cargo.toml`.
2. Bump `Version:` in `packaging/rpm/netwatch.spec` and add a `%changelog`
   entry. `tests/packaging.rs` fails until the two versions match.
3. Write the `CHANGELOG.md` entry.
4. Commit, merge to `main`, tag `vX.Y.Z`, push the tag.

The release workflow then builds every target, produces the packages,
generates `SHA256SUMS`, attests provenance, publishes to crates.io, and
attaches everything to the GitHub release. Homebrew and Scoop follow on their
own. COPR builds when its webhook fires.

## Container image

`ghcr.io/matthart1983/netwatch`, multi-arch (amd64 + arm64), built from the
musl-static release binary on an Alpine base — about 26 MB.

```sh
docker run --rm -it --net=host --pid=host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  ghcr.io/matthart1983/netwatch
```

Each flag earns its place:

| Flag | Without it |
|---|---|
| `--net=host` | netwatch sees the container's veth, not the host's traffic |
| `--pid=host` | no process attribution: `/proc/<pid>/fd` is the container's |
| `--cap-add=NET_RAW` | packet capture fails with `socket: Operation not permitted` |
| `--cap-add=NET_ADMIN` | interface state and some probes degrade |

The image is not `scratch`. netwatch shells out to `ss` and `ip` (iproute2)
for the connection table and routes, `ping` (iputils) for gateway and internet
RTT, and `iw` for wireless signal; without `ss` in particular the Connections,
Processes and Egress tabs are simply empty. Traceroute is native on Linux and
needs no binary. `chronyc` is left out, so Diagnose reports NTP clock offset as
unmeasured rather than guessing.

Verified in the image (15-second live sample, rootless podman, host network):
DNS, gateway, link, wifi, TCP socket metrics and STUN checks all report their
inputs as available — the same profile as a host run. **Packet capture needs a
rootful container**: rootless Docker or podman cannot grant `CAP_NET_RAW`, and
capture fails even with `--cap-add`. Use `sudo docker run …`, or run netwatch
outside a container if you mainly want the Packets tab.

## Channels waiting on an account

Prepared here, but each needs a login CI cannot have:

- **winget** — `packaging/winget/`, generated per release by
  `scripts/winget-manifest.sh <tag>`. Needs a fork of `microsoft/winget-pkgs`.
  Neither netwatch nor its closest competitor is on winget today.
- **AUR** — no action needed. `netwatch-tui` (source) tracks releases closely;
  `netwatch-tui-bin` lags by a release and ships no completions or man page.
  Both are other people's packages, so the most that is warranted is a comment
  on the -bin package when it falls behind.
- **nixpkgs** — no action needed. `r-ryantm`, the nixpkgs update bot, opens the
  bump PRs (it did 0.30.0), so the package catches up on its own cadence
  rather than ours. Only step in if it stalls for several releases.

## Setting up COPR (one-off)

One browser step, then a script.

1. **Get an API token.** Log in at <https://copr.fedorainfracloud.org> with a
   Fedora account, open <https://copr.fedorainfracloud.org/api/> and save the
   config block it shows to `~/.config/copr`. It looks like:

   ```ini
   [copr-cli]
   login = ...
   username = ...
   token = ...
   copr_url = https://copr.fedorainfracloud.org
   ```

2. **Run the setup.** `scripts/copr-setup.sh` creates the project, registers
   `packaging/rpm/netwatch.spec` as an SCM package against `main`, and starts
   the first build. It uses the COPR API directly, so it needs nothing
   installed beyond curl, and is safe to re-run.

3. **Wire up releases.** Add `COPR_LOGIN`, `COPR_TOKEN` and `COPR_USERNAME` as
   repository secrets; the `copr` job in `release.yml` then asks COPR to
   rebuild on every tag. Without them that job skips, so nothing breaks. This
   replaces the webhook the COPR UI offers.

4. Once a build succeeds, add to the README:
   `sudo dnf copr enable <user>/netwatch && sudo dnf install netwatch`.

The spec has not been built yet — the first COPR build is also its first real
test. Expect to iterate on `BuildRequires` once.
