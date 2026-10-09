#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Use netkit-cni's existing test workloads; never replace the cluster's CNI.
NAMESPACE="${E2E_NETKIT_NAMESPACE:-netkit-test}"
SOURCE="${E2E_NETKIT_SOURCE:-same-a}"
SAME_NODE="${E2E_NETKIT_SAME_NODE:-same-b}"
CROSS_NODE="${E2E_NETKIT_CROSS_NODE:-cross-b}"
PORT="${E2E_NETKIT_PORT:-8080}"
IMAGE="${E2E_IMAGE:?set E2E_IMAGE to the built agent image available on every test node}"
ARTIFACT_DIR="${E2E_ARTIFACT_DIR:-$(mktemp -d)}"
TRACE_PID=""

cleanup() {
  if [ -n "$TRACE_PID" ]; then
    kill -INT "$TRACE_PID" 2>/dev/null || true
    wait "$TRACE_PID" || true
  fi
}
trap cleanup EXIT

for command in kubectl jq timeout; do
  command -v "$command" >/dev/null || { echo "error: $command is required" >&2; exit 1; }
done
mkdir -p "$ARTIFACT_DIR"
make build

fail() {
  echo "FAIL: $*; artifacts: $ARTIFACT_DIR" >&2
  exit 1
}

source_node="$(kubectl -n "$NAMESPACE" get pod "$SOURCE" -o jsonpath='{.spec.nodeName}')"
for destination in "$SAME_NODE" "$CROSS_NODE"; do
  node="$(kubectl -n "$NAMESPACE" get pod "$destination" -o jsonpath='{.spec.nodeName}')"
  ip="$(kubectl -n "$NAMESPACE" get pod "$destination" -o jsonpath='{.status.podIP}')"
  expected=2
  if [ "$destination" = "$SAME_NODE" ]; then
    [ "$node" = "$source_node" ] || fail "$destination must be on the source node"
  else
    [ "$node" != "$source_node" ] || fail "$destination must be on a different node"
    expected=4
  fi
  output="$ARTIFACT_DIR/$destination.ndjson"
  timeout --signal=INT --kill-after=10s 90s ./bin/kubectl-datapath \
    trace pod "$NAMESPACE/$SOURCE" --to "pod/$NAMESPACE/$destination" \
    --agent-image "$IMAGE" --no-tui >"$output" 2>"$ARTIFACT_DIR/$destination.err" &
  TRACE_PID=$!
  ready=0
  for _ in $(seq 1 60); do
    kill -0 "$TRACE_PID" 2>/dev/null || fail "trace exited before readiness"
    if jq -se --argjson expected "$expected" \
      '[.[] | select(.kind == "status" and .interface != null) | .attachment_id] | unique | length == $expected' \
      "$output" >/dev/null; then
      ready=1
      break
    fi
    sleep 1
  done
  [ "$ready" = 1 ] || fail "timed out waiting for all attachments"
  kubectl -n "$NAMESPACE" exec "$SOURCE" -- python -c \
    'import sys, urllib.request; r = urllib.request.urlopen(sys.argv[1], timeout=5); assert r.status == 200; r.read()' \
    "http://$ip:$PORT/" || fail "HTTP request to $destination failed"
  sleep 1
  kill -INT "$TRACE_PID"
  status=0
  wait "$TRACE_PID" || status=$?
  TRACE_PID=""
  [ "$status" = 0 ] || [ "$status" = 130 ] || fail "trace exited with status $status"
  [ ! -s "$ARTIFACT_DIR/$destination.err" ] || fail "trace reported errors"
  jq -se --argjson expected "$expected" '
    [.[] | select(.kind == "status" and .final == true)] as $final |
    ($final | length == $expected) and
    all($final[]; .complete == true and (.lost // 0) == 0 and
      (.transport_lost // 0) == 0 and
      (.diagnostics | length == 2) and
      all(.diagnostics[]; .seen == (.parse_rejected + .filtered + .emitted + .lost))) and
    all(["source", "destination"][]; . as $side |
      any($final[]; .side == $side and .interface_kind == "netkit" and .interface_mode == "L3" and
        .interface_master == "nk-vrf" and .interface_vrf_table == 100))
  ' "$output" >/dev/null || fail "metadata or final diagnostics are incorrect"
  for side in source destination; do
    for direction in ingress egress; do
      jq -se --arg side "$side" --arg direction "$direction" '
        any(.[]; .kind == "packet" and .side == $side and .direction == $direction and
          .point == "pod-boundary/tcx" and .interface_kind == "netkit" and .interface_mode == "L3")
      ' "$output" >/dev/null || fail "$side $direction has no netkit packet evidence"
    done
  done
  if [ "$expected" = 4 ]; then
    for side in transit-source transit-destination; do
      jq -se --arg side "$side" \
        'any(.[]; .kind == "transit" and .side == $side and .encapsulation == "native")' \
        "$output" >/dev/null || fail "$side has no native transit"
    done
  else
    jq -se 'all(.[]; .kind != "transit")' "$output" >/dev/null ||
      fail "same-node trace unexpectedly captured transit"
  fi
  ./bin/kubectl-datapath replay --no-tui "$output" >"$ARTIFACT_DIR/$destination.replay.ndjson"
  jq -se 'any(.[]; .interface_kind == "netkit" and .interface_mode == "L3" and
    (.diagnostics | length) == 2)' "$ARTIFACT_DIR/$destination.replay.ndjson" >/dev/null ||
    fail "replay lost interface metadata or diagnostics"
  echo "PASS: $SOURCE -> $destination"
done
echo "Artifacts: $ARTIFACT_DIR"
