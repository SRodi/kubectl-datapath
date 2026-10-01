#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CNI="${CNI:-kindnet}"
case "$CNI" in
  kindnet|flannel|cilium|calico) ;;
  *) echo "error: unsupported CNI '$CNI'" >&2; exit 1 ;;
esac

KIND_VERSION="${KIND_VERSION:-v0.33.0}"
CILIUM_VERSION="${CILIUM_VERSION:-1.20.2}"
CALICO_VERSION="${CALICO_VERSION:-v3.32.2}"
FLANNEL_VERSION="${FLANNEL_VERSION:-v0.28.9}"
CNI_PLUGINS_VERSION="${CNI_PLUGINS_VERSION:-v1.9.1}"
CLUSTER="${E2E_CLUSTER:-kubectl-datapath-ci-${CNI}}"
EXISTING_CLUSTER="${E2E_EXISTING_CLUSTER:-0}"
KEEP_CLUSTER="${E2E_KEEP_CLUSTER:-0}"
IMAGE="${E2E_IMAGE:-kubectl-datapath:e2e}"
AGENT_NAMESPACE="${E2E_AGENT_NAMESPACE:-kube-system}"
IMAGE_PULL_SECRET="${E2E_IMAGE_PULL_SECRET:-}"
NAMESPACE="kubectl-datapath-e2e"
ARTIFACT_DIR="${E2E_ARTIFACT_DIR:-$(mktemp -d)}"
TRACE_PID=""
CREATED_CLUSTER=0
SOURCE_NODE=""
DESTINATION_NODE=""
SOURCE_PREVIOUS_ROLE=""
DESTINATION_PREVIOUS_ROLE=""

case "$CNI" in
  cilium|calico) DEFAULT_POLICY_ENFORCEMENT=1 ;;
  *) DEFAULT_POLICY_ENFORCEMENT=auto ;;
esac
ENFORCES_POLICY="${E2E_ENFORCES_NETWORK_POLICY:-$DEFAULT_POLICY_ENFORCEMENT}"
case "$ENFORCES_POLICY" in
  0|1|auto) ;;
  *) echo "error: E2E_ENFORCES_NETWORK_POLICY must be 0, 1, or auto" >&2; exit 1 ;;
esac

mkdir -p "$ARTIFACT_DIR"

log() {
  printf '== [%s] %s ==\n' "$CNI" "$*"
}

fail() {
  echo "FAIL: $*" >&2
  for file in "$ARTIFACT_DIR"/*.ndjson "$ARTIFACT_DIR"/*.err; do
    [ -f "$file" ] || continue
    echo "--- $file" >&2
    tail -40 "$file" >&2
  done
  exit 1
}

collect_diagnostics() {
  log "collecting failure diagnostics in $ARTIFACT_DIR"
  kubectl get pods -A -o wide >"$ARTIFACT_DIR/cluster-pods.txt" 2>&1 || true
  kubectl get events -A --sort-by=.metadata.creationTimestamp \
    >"$ARTIFACT_DIR/cluster-events.txt" 2>&1 || true
  kubectl describe nodes >"$ARTIFACT_DIR/nodes.txt" 2>&1 || true
  kubectl -n "$NAMESPACE" describe pods >"$ARTIFACT_DIR/application-pods.txt" 2>&1 || true
  kubectl -n kube-flannel logs -l app=flannel --all-containers --prefix \
    >"$ARTIFACT_DIR/flannel.log" 2>&1 || true
  if [ "$CREATED_CLUSTER" = "1" ]; then
    timeout 90s kind export logs "$ARTIFACT_DIR/kind" --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    collect_diagnostics
  fi
  if [ -n "$TRACE_PID" ]; then
    kill -INT "$TRACE_PID" >/dev/null 2>&1 || true
    wait "$TRACE_PID" >/dev/null 2>&1 || true
  fi
  kubectl delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  if [ -n "$SOURCE_NODE" ]; then
    if [ -n "$SOURCE_PREVIOUS_ROLE" ]; then
      kubectl label node "$SOURCE_NODE" "datapath.e2e/role=$SOURCE_PREVIOUS_ROLE" --overwrite >/dev/null 2>&1 || true
    else
      kubectl label node "$SOURCE_NODE" datapath.e2e/role- >/dev/null 2>&1 || true
    fi
  fi
  if [ -n "$DESTINATION_NODE" ]; then
    if [ -n "$DESTINATION_PREVIOUS_ROLE" ]; then
      kubectl label node "$DESTINATION_NODE" "datapath.e2e/role=$DESTINATION_PREVIOUS_ROLE" --overwrite >/dev/null 2>&1 || true
    else
      kubectl label node "$DESTINATION_NODE" datapath.e2e/role- >/dev/null 2>&1 || true
    fi
  fi
  if [ "$CREATED_CLUSTER" = "1" ] && [ "$KEEP_CLUSTER" != "1" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command '$1' is not installed" >&2
    exit 1
  }
}

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo "$@"
    return
  fi
  return 1
}

prepare_flannel_host() {
  local ipv4_bridge_sysctl="/proc/sys/net/bridge/bridge-nf-call-iptables"
  if [ ! -e "$ipv4_bridge_sysctl" ]; then
    require_command modprobe
    log "loading host br_netfilter module required by Flannel"
    run_as_root modprobe br_netfilter ||
      fail "Flannel requires br_netfilter; load it as root before running the E2E test"
  fi
  [ -e "$ipv4_bridge_sysctl" ] ||
    fail "br_netfilter loaded without exposing $ipv4_bridge_sysctl"
  if [ "$(cat "$ipv4_bridge_sysctl")" != "1" ]; then
    run_as_root sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null ||
      fail "Flannel requires net.bridge.bridge-nf-call-iptables=1"
  fi
}

for command in kubectl jq; do
  require_command "$command"
done
if [ "$EXISTING_CLUSTER" != "1" ]; then
  require_command docker
  if [ "$CNI" = "flannel" ]; then
    prepare_flannel_host
  fi
fi

create_cluster() {
  require_command kind
  log "creating Kind cluster $CLUSTER"
  if [ "$CNI" = "cilium" ]; then
    require_command cilium
  fi
  make "kind-${CNI}-up" \
    E2E_CLUSTER="$CLUSTER" \
    KIND_VERSION="$KIND_VERSION" \
    CILIUM_VERSION="$CILIUM_VERSION" \
    CALICO_VERSION="$CALICO_VERSION" \
    FLANNEL_VERSION="$FLANNEL_VERSION" \
    CNI_PLUGINS_VERSION="$CNI_PLUGINS_VERSION"
  CREATED_CLUSTER=1
}

if [ "$EXISTING_CLUSTER" != "1" ]; then
  create_cluster
else
  log "using existing context $(kubectl config current-context)"
  kubectl cluster-info >/dev/null
fi

log "building client"
make build

if [ "$EXISTING_CLUSTER" != "1" ]; then
  log "building and loading agent image $IMAGE"
  make kind-load IMAGE="$IMAGE" E2E_CLUSTER="$CLUSTER"
fi

mapfile -t NODES < <(
  kubectl get nodes -o json |
    jq -r '.items[]
      | select(.spec.unschedulable != true)
      | select(all(.spec.taints[]?; .effect != "NoSchedule"))
      | .metadata.name' |
    sort
)
if [ "${#NODES[@]}" -lt 2 ]; then
  fail "E2E requires two schedulable nodes; found ${#NODES[@]}"
fi
SOURCE_NODE="${NODES[0]}"
DESTINATION_NODE="${NODES[1]}"
SOURCE_PREVIOUS_ROLE="$(kubectl get node "$SOURCE_NODE" -o jsonpath='{.metadata.labels.datapath\.e2e/role}')"
DESTINATION_PREVIOUS_ROLE="$(kubectl get node "$DESTINATION_NODE" -o jsonpath='{.metadata.labels.datapath\.e2e/role}')"
kubectl label node "$SOURCE_NODE" datapath.e2e/role=source --overwrite
kubectl label node "$DESTINATION_NODE" datapath.e2e/role=destination --overwrite

log "deploying cross-node test applications"
kubectl apply -f deploy/e2e/apps.yaml
kubectl -n "$NAMESPACE" rollout status deployment/frontend --timeout=180s
kubectl -n "$NAMESPACE" rollout status deployment/backend --timeout=180s
kubectl -n kube-system rollout status deployment/coredns --timeout=180s

FRONTEND="$(kubectl -n "$NAMESPACE" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
BACKEND="$(kubectl -n "$NAMESPACE" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"
if [ "$(kubectl -n "$NAMESPACE" get pod "$FRONTEND" -o jsonpath='{.spec.nodeName}')" = \
     "$(kubectl -n "$NAMESPACE" get pod "$BACKEND" -o jsonpath='{.spec.nodeName}')" ]; then
  fail "frontend and backend were not scheduled cross-node"
fi

TRACE_ARGS=(
  trace pod "$NAMESPACE/$FRONTEND"
  --to "service/$NAMESPACE/backend"
  --agent-image "$IMAGE"
  --agent-namespace "$AGENT_NAMESPACE"
  --no-tui
)
if [ -n "$IMAGE_PULL_SECRET" ]; then
  TRACE_ARGS+=(--agent-image-pull-secret "$IMAGE_PULL_SECRET")
fi

wait_for_trace_context() {
  local file="$1"
  for _ in $(seq 1 120); do
    if grep -q '"kind":"trace_context"' "$file" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$TRACE_PID" >/dev/null 2>&1; then
      wait "$TRACE_PID" || true
      fail "trace exited before reporting context"
    fi
    sleep 1
  done
  fail "timed out waiting for trace context"
}

start_trace() {
  local name="$1"
  local output="$ARTIFACT_DIR/$name.ndjson"
  local errors="$ARTIFACT_DIR/$name.err"
  : >"$output"
  : >"$errors"
  timeout --signal=INT --kill-after=10s 90s \
    ./bin/kubectl-datapath "${TRACE_ARGS[@]}" >"$output" 2>"$errors" &
  TRACE_PID=$!
  wait_for_trace_context "$output"

  local session
  session="$(jq -sr 'map(select(.kind == "trace_context"))[0].session_id // empty' "$output")"
  [ -n "$session" ] || fail "trace context did not include a session ID"
  local pod_state count nodes
  for _ in $(seq 1 30); do
    pod_state="$(kubectl -n "$AGENT_NAMESPACE" get pods \
      -l "datapath.kubernetes.io/session=$session" -o json 2>/dev/null || true)"
    if [ -z "$pod_state" ]; then
      pod_state='{"items":[]}'
    fi
    count="$(jq -r '.items | length' <<<"$pod_state")"
    nodes="$(jq -r '[.items[].spec.nodeName] | unique | length' <<<"$pod_state")"
    if [ "$count" -ge 2 ] && [ "$count" -eq "$nodes" ]; then
      return 0
    fi
    sleep 1
  done
  fail "expected exactly one agent on every involved node"
}

stop_trace() {
  kill -INT "$TRACE_PID" >/dev/null 2>&1 || true
  wait "$TRACE_PID" >/dev/null 2>&1 || true
  TRACE_PID=""
}

request_backend() {
  kubectl -n "$NAMESPACE" exec deployment/frontend -- \
    wget -q -T 5 -O- "http://backend.$NAMESPACE.svc.cluster.local"
}

assert_jq() {
  local file="$1"
  local expression="$2"
  local description="$3"
  jq -s -e "$expression" "$file" >/dev/null || fail "$description"
}

log "baseline: expect Service traffic at both Pod boundaries"
start_trace baseline
request_backend >/dev/null || fail "baseline request failed"
sleep 3
stop_trace
BASELINE="$ARTIFACT_DIR/baseline.ndjson"
assert_jq "$BASELINE" \
  'any(.[]; .kind == "connect" and .side == "source" and .dst_port == 80)' \
  "baseline trace has no application connect evidence"
assert_jq "$BASELINE" \
  'any(.[]; .kind == "packet" and .side == "source" and .protocol == 6 and (((.tcp_flags / 2) | floor) % 2) == 1)' \
  "baseline trace has no source SYN"
assert_jq "$BASELINE" \
  'any(.[]; .kind == "packet" and .side == "backend" and .protocol == 6 and (((.tcp_flags / 2) | floor) % 2) == 1)' \
  "baseline trace has no backend SYN"
assert_jq "$BASELINE" \
  'all(.[]; (.lost // 0) == 0)' \
  "baseline trace reported event loss"
if [ "$CNI" != "calico" ]; then
  assert_jq "$BASELINE" \
    'any(.[]; .kind == "transit" and .side == "transit-source") and
     any(.[]; .kind == "transit" and .side == "transit-destination")' \
    "baseline trace has no two-node transit evidence"
fi

log "ingress policy scenario"
kubectl apply -f deploy/e2e/deny-backend-ingress.yaml
sleep 3
start_trace ingress-deny
if request_backend >/dev/null 2>&1; then
  OBSERVED_POLICY_ENFORCEMENT=0
else
  OBSERVED_POLICY_ENFORCEMENT=1
fi
if [ "$ENFORCES_POLICY" = "auto" ]; then
  ENFORCES_POLICY="$OBSERVED_POLICY_ENFORCEMENT"
  log "detected NetworkPolicy enforcement=$ENFORCES_POLICY"
elif [ "$ENFORCES_POLICY" != "$OBSERVED_POLICY_ENFORCEMENT" ]; then
  fail "NetworkPolicy enforcement did not match E2E_ENFORCES_NETWORK_POLICY=$ENFORCES_POLICY"
fi
sleep 3
stop_trace
INGRESS="$ARTIFACT_DIR/ingress-deny.ndjson"
assert_jq "$INGRESS" \
  'any(.[]; .kind == "trace_context" and
    any(.trace.policies[]?; .name == "deny-backend-ingress" and .scope == "destination ingress"))' \
  "ingress policy was not included in trace context"
if [ "$ENFORCES_POLICY" = "1" ]; then
  assert_jq "$INGRESS" \
    'any(.[]; .kind == "packet" and .side == "source" and .protocol == 6 and (((.tcp_flags / 2) | floor) % 2) == 1) and
     (any(.[]; .kind == "packet" and .side == "backend" and .protocol == 6 and (((.tcp_flags / 2) | floor) % 2) == 1) | not)' \
    "ingress-denied trace did not stop before the backend boundary"
fi
kubectl delete -f deploy/e2e/deny-backend-ingress.yaml --ignore-not-found

log "egress policy refresh and DNS prerequisite scenario"
start_trace egress-deny
kubectl apply -f deploy/e2e/deny-frontend-egress.yaml
for _ in $(seq 1 30); do
  if jq -s -e 'any(.[]; .kind == "trace_context" and
    any(.trace.policies[]?; .name == "deny-frontend-egress" and .scope == "source egress"))' \
    "$ARTIFACT_DIR/egress-deny.ndjson" >/dev/null; then
    break
  fi
  sleep 1
done
assert_jq "$ARTIFACT_DIR/egress-deny.ndjson" \
  'any(.[]; .kind == "trace_context" and
    any(.trace.policies[]?; .name == "deny-frontend-egress" and .scope == "source egress"))' \
  "running trace did not refresh egress policy context"
if [ "$ENFORCES_POLICY" = "1" ]; then
  request_backend >/dev/null 2>&1 && fail "backend request succeeded despite egress deny"
else
  request_backend >/dev/null || fail "non-enforcing CNI unexpectedly blocked egress"
fi
sleep 3
stop_trace
EGRESS="$ARTIFACT_DIR/egress-deny.ndjson"
if [ "$ENFORCES_POLICY" = "1" ]; then
  assert_jq "$EGRESS" \
    'any(.[]; .kind == "packet" and .side == "source" and .protocol == 17 and .dst_port == 53)' \
    "egress-denied trace has no source DNS query"
  assert_jq "$EGRESS" \
    '(any(.[]; .kind == "packet" and .side == "dns" and .protocol == 17 and .dst_port == 53) | not)' \
    "egress-denied DNS query unexpectedly reached a CoreDNS boundary"
fi
kubectl delete -f deploy/e2e/deny-frontend-egress.yaml --ignore-not-found

log "PASS"
