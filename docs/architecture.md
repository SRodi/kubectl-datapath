# Architecture and design

This document explains how `kubectl-datapath` gathers evidence, how that
evidence is interpreted, and why the project deliberately avoids stronger
claims.

## Design goals

1. **Answer one path question.** A trace always has a source Pod and an explicit
   Pod or Service destination.
2. **Show evidence before conclusions.** Observation points and uncertainty are
   visible in the primary TUI map.
3. **Keep cluster access local.** Kubernetes credentials never enter capture
   agents.
4. **Leave no permanent privileged component.** Agents exist only for the
   trace.
5. **Scale by node, not attachment.** One agent Pod on each involved node hosts
   independent capture sessions.
6. **Keep artifacts reviewable.** Observations are versioned NDJSON; diagrams
   are Mermaid stored beside the code.

## System architecture

```mermaid
flowchart TB
    CLI["Local client<br/>credentials + destination resolver"]
    K8S["Kubernetes metadata<br/>Pods · Services · EndpointSlices · Policies"]
    SA["Source-node agent<br/>source veth + connect + underlay"]
    DA["Destination-node agent<br/>destination veths + underlay"]
    OBS["Versioned observations<br/>packet · connect · transit · status"]
    COR["Evidence correlator<br/>attempts · DNS · translation · freshness"]
    UI["TUI / NDJSON"]

    CLI --> K8S
    K8S -->|"create / stream logs / delete"| SA
    K8S -->|"create / stream logs / delete"| DA
    SA --> OBS
    DA --> OBS
    OBS --> COR --> UI
```

### Trust boundary

The client owns Kubernetes credentials, resource resolution, metadata
enrichment, correlation, and presentation.

Each agent Pod is:

- pinned to one involved node;
- privileged, host-networked, and host-PID;
- mounted read-only to host procfs and cgroup v2;
- created without a ServiceAccount token;
- bounded by a 30-minute deadline;
- deleted when the trace ends.

The privilege is broad at the node boundary, so minimizing agent lifetime and
count matters. Grouping by node reduces a typical cross-node Service trace from
six privileged Pods to two without combining evidence identities.

## Trace lifecycle

```mermaid
flowchart TB
    A["Resolve source and destination"]
    B["Resolve ready Service and DNS backends"]
    C["Build capture targets grouped by node"]
    D["Create one agent Pod per involved node"]
    E["Open independent capture sessions"]
    F["Stream and enrich observations"]
    G["Select newest relevant evidence"]
    H["Render map, diagnosis, details, and history"]
    I["Delete agents"]

    A --> B --> C --> D --> E --> F --> G --> H --> I
```

All targets are known before agents start. A node agent receives a list of
Pod-UID or route targets, opens one capture session for each, and multiplexes
their events onto one log stream.

The sessions remain independent:

- separate BPF objects and maps;
- separate ring buffers;
- separate attachment IDs and sides;
- separate readiness and error attribution;
- separate event-loss counters.

This preserves the existing evidence model while reducing Kubernetes objects
and startup overhead.

## Datapath observation model

The TUI map represents network namespaces and instrumented boundaries, not an
idealized packet-delivery promise.

```mermaid
flowchart TB
    APP["Application socket<br/>connect intent"]

    subgraph SN["Source node"]
        SP["Source Pod network namespace"]
        SV["Source host-veth<br/>pre/post Pod boundary"]
        SU["Route-selected underlay interface"]
        SP --> SV --> SU
    end

    NET["Native route or VXLAN underlay"]

    subgraph DN["Destination node"]
        DU["Route-selected underlay interface"]
        DV["Destination host-veth"]
        DP["Destination Pod network namespace"]
        DU --> DV --> DP
    end

    APP --> SP
    SU --> NET --> DU
```

### What each point proves

| Observation point | Proves | Does not prove |
|---|---|---|
| `connect()` entry | Destination supplied by the application | Successful connection or packet transmission |
| Source host-veth | Packet crossed the selected Pod boundary | Packet passed every source-node policy or routing hook |
| Source underlay | Matching packet reached the selected node interface | Remote-node arrival |
| Destination underlay | Matching packet was visible on the destination node interface | Delivery to the destination Pod |
| Destination host-veth | Matching packet reached that Pod boundary | Application acceptance or processing |

Capture programs attach at explicit kernel points. Other CNI programs may run
before or after them. The UI therefore says “observed” and “no matching
evidence,” not “delivered” and “dropped.”

## Service and DNS translation

For a Service trace, the client correlates three address views:

```mermaid
flowchart TB
    A["Application intent<br/>Service ClusterIP"]
    B["Source Pod boundary<br/>Service or backend address"]
    C["Backend Pod boundary<br/>selected Pod address"]

    A -->|"compare destination"| B
    B -->|"compare selected TCP attempt"| C
```

A changed address localizes translation relative to observation points. It does
not identify the specific kube-proxy or CNI program responsible.

DNS is a prerequisite path, not background noise:

```mermaid
flowchart TB
    A["Resolver intent<br/>kube-dns Service"]
    B["Source boundary<br/>Service or CoreDNS address"]
    C["Source underlay"]
    D["CoreDNS boundary"]
    E["DNS response"]

    A --> B --> C --> D --> E
```

If a newer DNS query has no response, it becomes the primary focus and an older
backend TCP attempt becomes historical only when the DNS and backend connect
intents came from the same source cgroup. DNS qnames are not captured, so the
UI does not claim that the query named the selected Service. This prevents
sidecar DNS traffic from casually replacing the application path.

### Socket load balancing and policy

Socket-level Service translation and NetworkPolicy enforcement may occur at
different hooks. For example, Cilium can translate `kube-dns` to a CoreDNS Pod
at a cgroup socket hook, while enforcing egress later in the endpoint datapath.
The tracer may therefore observe:

```text
● application intended kube-dns
● source veth carries the translated CoreDNS address
× no matching packet at the source underlay
```

That localizes the evidence gap inside the source node. A selecting egress
policy is useful context, but without direct policy-verdict capture it remains
context rather than proof of the responsible rule.

## Correlation and freshness

### TCP attempts

A TCP attempt is keyed by:

- protocol;
- source Pod address;
- client port;
- initial TCP sequence.

Retransmitted SYNs remain part of the same attempt. Backend and transit SYNs
must match the initial sequence, preventing an old connection that reused a
client tuple from satisfying the latest path.

### Current versus historical evidence

The primary map follows the newest relevant activity:

1. newer unresolved DNS activity;
2. otherwise, the newest TCP attempt;
3. older attempts remain timestamped history.

Event loss changes a missing point to **incomplete**. Cross-node events retain
node-local monotonic order; clocks from different nodes are never used to
calculate latency.

## Capture implementation

| Capture | Attachment | Filter |
|---|---|---|
| Pod packets | TCX on host-side veth ingress and egress | Selected Pod interface; client trace correlation |
| Application intent | BTF/fentry on `__sys_connect` | Selected source Pod cgroup IDs |
| Native transit | TCX on route-selected interface | Both selected inner addresses |
| VXLAN transit | TCX with UDP `8472` / `4789` decoding | Both selected inner addresses |

The agent resolves Pod interfaces from the Pod UID and host cgroup/procfs
state. Selected source, destination, Service, backend, and DNS addresses are
loaded into a BPF map so unrelated traffic on busy Pod and CoreDNS veths is
discarded before ring-buffer emission. Underlay interfaces come from a route
lookup to the remote Node InternalIP; no default node-interface name is
assumed.

Pod interface discovery currently expects `eth0`. The application path uses
the Pod's primary address; secondary dual-stack addresses and Multus interfaces
are explicit current limitations.

Current inner-tuple decoding supports native IPv4/IPv6 and VXLAN. Geneve,
IP-in-IP, WireGuard, and IPsec are not decoded.

## Important design choices

| Choice | Why | Tradeoff |
|---|---|---|
| One `trace pod ... --to ...` workflow | Keeps the mental model goal-oriented | Requires an explicit destination |
| One ephemeral agent Pod per involved node | Reduces privileged Pods, scheduling, logs, and cleanup | One agent failure removes all capture points on that node |
| Independent BPF session per attachment | Preserves isolation, attribution, and current map semantics | More BPF objects and ring buffers inside each agent |
| No persistent DaemonSet | No always-on privileged component or installation lifecycle | Higher startup latency for each trace |
| Credentials only in the client | Smaller credential and trust surface | Metadata enrichment depends on the client remaining connected |
| Evidence, not delivery verdicts | Avoids false certainty across CNIs and kernel hooks | Users must interpret gaps rather than receive simplistic pass/fail output |
| Route-selected interfaces | Works without assuming `eth0` or a specific CNI | Unsupported or encrypted underlays can hide inner traffic |
| Separate node-local chronology | Avoids invalid cross-node clock comparisons | No cross-node latency calculation |
| Versioned NDJSON | Replayable, testable, automation-friendly evidence | Schema changes require compatibility discipline |
| Stop when Service backends change | Prevents stale attachments from being shown as current | Long-running traces must restart after rollouts or readiness changes |
| Bounded backend instrumentation | Controls privileged attachment and BPF cost | Uninstrumented selected backends are shown as unavailable |
| Mermaid in Markdown | Responsive, reviewable, and easy to update with code | Rendering depends on Mermaid support in the viewer |

### Why not share one BPF object per node?

Boundary and transit sessions currently require different per-object capture
modes and selected-address maps. Keeping separate objects avoids cross-target
state coupling and makes errors and loss attributable. Sharing programs or maps
may reduce node-agent memory later, but only if the event model continues to
identify the exact attachment.

### Why not deploy a DaemonSet?

A DaemonSet would reduce trace startup time, but it would leave a privileged
observer running on every node and introduce installation, upgrade, RBAC, and
multi-user isolation concerns. The current design favors on-demand debugging
with explicit lifetime.

## Compatibility and extension points

Unsupported capture paths must return compatibility evidence rather than
silently changing semantics.

The `capture.Strategy` interface allows future implementations, such as
cgroup-v2 packet hooks, classic tc, Cilium netkit, or CNI-specific verdict
adapters, without changing the observation schema or TUI model.

When adding a new observation point:

1. define exactly what it proves and does not prove;
2. preserve attachment identity and loss accounting;
3. add correlation tests for stale and unrelated traffic;
4. update the Mermaid diagrams in this document;
5. add replay data when the event shape or semantics change.
