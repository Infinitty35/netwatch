#!/usr/bin/env bash
# Generate winget manifests for a released tag.
#
#   scripts/winget-manifest.sh v0.32.1
#
# Writes packaging/winget/generated/. Submission steps are in
# packaging/winget/README.md. Run from the repository root.
set -euo pipefail

TAG="${1:?usage: winget-manifest.sh vX.Y.Z}"
VERSION="${TAG#v}"
REPO="matthart1983/netwatch"
ASSET="netwatch-windows-x86_64.exe.zip"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
OUT="packaging/winget/generated"
ID="MattHartley.netwatch"
# winget requires the release date of the version being submitted.
RELEASED=$(gh release view "${TAG}" -R "${REPO}" --json publishedAt --jq '.publishedAt[:10]')

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
echo "Downloading ${ASSET} from ${TAG}..."
curl -sSLf "${URL}" -o "${tmp}/${ASSET}"
SHA=$(sha256sum "${tmp}/${ASSET}" | awk '{print toupper($1)}')
echo "sha256: ${SHA}"

rm -rf "${OUT}" && mkdir -p "${OUT}"

cat > "${OUT}/${ID}.yaml" <<YAML
# Created with scripts/winget-manifest.sh
PackageIdentifier: ${ID}
PackageVersion: ${VERSION}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
YAML

cat > "${OUT}/${ID}.locale.en-US.yaml" <<YAML
PackageIdentifier: ${ID}
PackageVersion: ${VERSION}
PackageLocale: en-US
Publisher: Matt Hartley
PublisherUrl: https://github.com/matthart1983
PublisherSupportUrl: https://github.com/${REPO}/issues
PackageName: netwatch
PackageUrl: https://github.com/${REPO}
License: MIT
LicenseUrl: https://github.com/${REPO}/blob/main/LICENSE
ShortDescription: Real-time network diagnostics in your terminal
Description: |-
  Live per-connection throughput with application-protocol decoding, process
  attribution, packet and interface views, and a diagnostic engine that learns
  a per-network baseline and opens an issue when that baseline breaks.

  Packet capture requires Npcap (https://npcap.com), which winget cannot
  install for you. Install it before running netwatch.
Moniker: netwatch
Tags:
- network
- monitoring
- tui
- terminal
- packet-capture
- diagnostics
ReleaseNotesUrl: https://github.com/${REPO}/releases/tag/${TAG}
ManifestType: defaultLocale
ManifestVersion: 1.6.0
YAML

cat > "${OUT}/${ID}.installer.yaml" <<YAML
PackageIdentifier: ${ID}
PackageVersion: ${VERSION}
ReleaseDate: ${RELEASED}
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
- RelativeFilePath: netwatch-windows-x86_64.exe
  PortableCommandAlias: netwatch
Installers:
- Architecture: x64
  InstallerUrl: ${URL}
  InstallerSha256: ${SHA}
InstallationNotes: |-
  Packet capture requires Npcap: https://npcap.com/#download
ManifestType: installer
ManifestVersion: 1.6.0
YAML

echo "Wrote:"
ls -1 "${OUT}"
