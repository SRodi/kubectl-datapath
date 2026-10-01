#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${MERMAID_CLI_IMAGE:-ghcr.io/mermaid-js/mermaid-cli/mermaid-cli:11.12.0@sha256:bad64c9d9ad917c8dfbe9d9e9c162b96f6615ff019b37058638d16eb27ce7783}"
SOURCE_DIR="docs/diagrams"
CONFIG="$SOURCE_DIR/mermaid-config.json"

render() {
  local output_dir="$1"
  mkdir -p "$output_dir"
  for source in "$SOURCE_DIR"/*.mmd; do
    local name
    name="$(basename "$source" .mmd)"
    docker run --rm \
      --user "$(id -u):$(id -g)" \
      --volume "$ROOT:/data" \
      "$IMAGE" \
      --input "$source" \
      --output "$output_dir/$name.svg" \
      --configFile "$CONFIG" \
      --backgroundColor white
  done
}

if [ "${1:-}" != "--check" ]; then
  render "$SOURCE_DIR"
  exit 0
fi

temporary="$(mktemp -d "$ROOT/.architecture-diagrams.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
relative_temporary="${temporary#"$ROOT"/}"
render "$relative_temporary"

for source in "$SOURCE_DIR"/*.mmd; do
  name="$(basename "$source" .mmd)"
  if ! cmp -s "$relative_temporary/$name.svg" "$SOURCE_DIR/$name.svg"; then
    echo "error: $SOURCE_DIR/$name.svg is stale; run 'make architecture-diagrams'" >&2
    exit 1
  fi
done
