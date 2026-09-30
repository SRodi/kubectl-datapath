#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 TAG CHECKSUMS OUTPUT" >&2
  exit 1
fi

tag="$1"
checksums="$2"
output="$3"
version="${tag#v}"

checksum() {
  local file="$1"
  local value
  value="$(awk -v file="$file" '$2 == file { print $1 }' "$checksums")"
  if [ -z "$value" ]; then
    echo "error: checksum not found for $file" >&2
    exit 1
  fi
  printf '%s' "$value"
}

linux_amd64="kubectl-datapath_${version}_linux_amd64.tar.gz"
linux_arm64="kubectl-datapath_${version}_linux_arm64.tar.gz"
darwin_amd64="kubectl-datapath_${version}_darwin_amd64.tar.gz"
darwin_arm64="kubectl-datapath_${version}_darwin_arm64.tar.gz"

cat >"$output" <<EOF
apiVersion: krew.googlecontainertools.github.com/v1alpha2
kind: Plugin
metadata:
  name: datapath
spec:
  version: "$tag"
  homepage: https://github.com/SRodi/kubectl-datapath
  shortDescription: Observe packet evidence in the Kubernetes datapath
  description: |
    Launches short-lived node agents and presents packet observations,
    attribution confidence, compatibility, and event loss in a terminal UI.
  platforms:
    - selector:
        matchLabels: {os: linux, arch: amd64}
      uri: https://github.com/SRodi/kubectl-datapath/releases/download/$tag/$linux_amd64
      sha256: "$(checksum "$linux_amd64")"
      bin: kubectl-datapath
    - selector:
        matchLabels: {os: linux, arch: arm64}
      uri: https://github.com/SRodi/kubectl-datapath/releases/download/$tag/$linux_arm64
      sha256: "$(checksum "$linux_arm64")"
      bin: kubectl-datapath
    - selector:
        matchLabels: {os: darwin, arch: amd64}
      uri: https://github.com/SRodi/kubectl-datapath/releases/download/$tag/$darwin_amd64
      sha256: "$(checksum "$darwin_amd64")"
      bin: kubectl-datapath
    - selector:
        matchLabels: {os: darwin, arch: arm64}
      uri: https://github.com/SRodi/kubectl-datapath/releases/download/$tag/$darwin_arm64
      sha256: "$(checksum "$darwin_arm64")"
      bin: kubectl-datapath
EOF
