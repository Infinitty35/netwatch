# AUR

Two AUR packages exist today, both maintained by other people:

| Package | Builds | Maintainer | Status at 2026-09-20 |
|---|---|---|---|
| `netwatch-tui` | from source | Dominiquini | current (0.32.0) |
| `netwatch-tui-bin` | release binary | kemelzaidan | a release behind (0.31.4) |

**It needs v0.33.0 or later.** The completions, man page and unit were added
after v0.32.0 was tagged, so the PKGBUILD's `package()` fails against the
0.32.0 source tarball. Verified by building it against `main`, where it
produces the expected layout.

`PKGBUILD` here is a replacement for the **-bin** package: it installs the
musl-static binary and takes the completions, man page, unit and licence from
the source tarball, which the current one does not ship.

Before using it, ask: the polite route is to open a comment on
<https://aur.archlinux.org/packages/netwatch-tui-bin> offering to
co-maintain, and only fall back to an orphan request if the maintainer is
unresponsive (AUR requires two weeks of inactivity for that).

With co-maintainer rights:

```sh
# One-off: an AUR account with an SSH key uploaded
git clone ssh://aur@aur.archlinux.org/netwatch-tui-bin.git
cp packaging/aur/PKGBUILD netwatch-tui-bin/
cd netwatch-tui-bin
updpkgsums                     # fills in the three sha256sums
makepkg --printsrcinfo > .SRCINFO
makepkg -si                    # build and install locally to check
git commit -am "netwatch-tui-bin 0.33.0" && git push
```

`updpkgsums` and `makepkg` are Arch-only, so this step needs an Arch box or
container: `podman run --rm -it -v "$PWD:/pkg" archlinux:base-devel`.
