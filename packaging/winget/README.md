# winget manifests

netwatch is not in [winget](https://github.com/microsoft/winget-pkgs) yet. These
are the manifests to submit, generated per release by
`scripts/winget-manifest.sh`.

The Windows release asset is a zip holding one portable `.exe`, so the manifest
uses `InstallerType: zip` with `NestedInstallerType: portable`. winget places the
binary on PATH; **Npcap is still a prerequisite** and winget cannot install it
for you, which is why it appears in the description and as an installation note.

## Submitting

```sh
# 1. Generate for the tag you want to publish
scripts/winget-manifest.sh v0.32.1

# 2. Fork microsoft/winget-pkgs, then copy the manifests into place
gh repo fork microsoft/winget-pkgs --clone --remote
mkdir -p winget-pkgs/manifests/m/MattHartley/netwatch/0.32.1
cp packaging/winget/generated/* winget-pkgs/manifests/m/MattHartley/netwatch/0.32.1/

# 3. Validate (Windows only — needs winget itself)
winget validate --manifest manifests/m/MattHartley/netwatch/0.32.1
winget install --manifest manifests/m/MattHartley/netwatch/0.32.1

# 4. Open the PR
cd winget-pkgs && git switch -c netwatch-0.32.1
git add manifests/m/MattHartley/netwatch && git commit -m "New version: MattHartley.netwatch version 0.32.1"
git push -u origin netwatch-0.32.1 && gh pr create --repo microsoft/winget-pkgs --fill
```

Microsoft's bot validates the PR and merges it if the manifest installs
cleanly. After the first submission, later versions can be done with
[wingetcreate](https://github.com/microsoft/winget-create) on a Windows box:
`wingetcreate update MattHartley.netwatch --version 0.32.1 --urls <zip-url> --submit`.

`PackageIdentifier` is `MattHartley.netwatch` — winget wants
`Publisher.Package`, and it cannot be changed after the first merge.
