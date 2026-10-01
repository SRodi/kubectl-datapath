# Security and threat model

`kubectl-datapath` is a privileged debugging tool. Its capture agents should be
treated as temporary node administrators, not as isolated application
workloads.

## Security boundaries

The local client:

- holds the user's Kubernetes credentials;
- resolves Kubernetes resources and enriches observations;
- creates, reads logs from, and deletes agent Pods;
- correlates and displays evidence.

Each agent Pod:

- runs as root with `privileged: true`, `hostPID: true`, and `hostNetwork: true`;
- mounts host procfs and cgroup v2 read-only;
- attaches eBPF programs to host interfaces and kernel functions;
- receives no ServiceAccount token;
- expires through `activeDeadlineSeconds` after 30 minutes;
- receives a graceful termination signal when the client exits normally so it
  can detach capture hooks and emit final evidence watermarks before deletion.

Normal cleanup requests a five-second Pod termination grace period and waits up
to ten seconds for the log stream to finish. If the stream does not finish,
cleanup reports that final capture status may be missing rather than claiming a
complete trace.

Keeping Kubernetes credentials out of agents prevents an agent from directly
using the caller's API permissions. It does not confine the agent. A privileged
host-PID process can inspect node processes and can potentially access host and
workload data outside the explicit read-only mounts.

## Protected assets

- Kubernetes API credentials held by the local client
- application traffic metadata and payload lengths
- process, cgroup, interface, and network-namespace metadata
- node and Pod confidentiality
- integrity of kernel networking state
- integrity and completeness of emitted observations

## Trust assumptions

- The local client machine and user account are trusted.
- The selected agent image is trusted and immutable.
- The Kubernetes API server, kubelet, and container runtime are trusted.
- Cluster admission policy restricts who can create privileged agent Pods.
- Node kernels correctly enforce eBPF verifier and attachment semantics.

Anyone who can create an arbitrary privileged Pod can normally obtain
node-root-equivalent access. Kubernetes RBAC cannot restrict Pod fields such as
`privileged`, `hostPID`, host paths, image, or command. A Role that grants agent
Pod creation is therefore a high-privilege grant unless an admission policy
also constrains the allowed Pod specification.

## Main threats and mitigations

| Threat | Current mitigation | Residual risk |
|---|---|---|
| Client credentials exposed to an agent | ServiceAccount automount is disabled and caller credentials remain local | The agent still has broad node access |
| Agent remains after a client crash | Pod deadline is 30 minutes | Exposure continues until deletion or deadline |
| Untrusted agent image executes as node root | Release images are versioned and can be pinned by digest | Mutable or privately rebuilt images require independent trust |
| Unauthorized user creates arbitrary privileged Pods | Use a dedicated group, namespace, and admission policy | RBAC alone cannot constrain the Pod specification |
| Observation loss produces a false gap | Ring-buffer loss and sequence-derived log-transport loss are reported separately; final per-attachment watermarks detect tail loss and missing/incomplete shutdown status | Complete loss before the first retained sequence cannot be distinguished from a late stream start; Kubernetes log rotation or truncation is surfaced as missing final status |
| Sensitive traffic metadata is retained | Agents emit selected tuples only and are deleted after the trace | NDJSON output and CI artifacts may contain cluster metadata |
| Agent changes host networking state | TCX links or owned classic TC filters are removed on session close and agents are short-lived | A harmless shared `clsact` qdisc can remain; process termination or kernel defects can leave state requiring inspection |

## Recommended deployment

1. Use a dedicated namespace such as `kubectl-datapath-agent`.
2. Label that namespace for privileged Pod Security only after accepting the
   node-level trust boundary.
3. Bind access to a dedicated operator group, not all developers.
4. Restrict the allowed agent image, command, labels, host paths, and security
   context with a ValidatingAdmissionPolicy or an equivalent policy engine.
5. Pin release agent images by digest where possible.
6. Audit Pod creation and deletion in the agent namespace.
7. Treat saved NDJSON and E2E artifacts as potentially sensitive operational
   data.

The following RBAC is the minimum used by the current client, but it is not a
complete security boundary without admission control:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kubectl-datapath-agent
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
    kubectl-datapath-agent: "true"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubectl-datapath-reader
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["pods", "services"]
    verbs: ["get", "list"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubectl-datapath-readers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubectl-datapath-reader
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: kubectl-datapath-users
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kubectl-datapath-agent-manager
  namespace: kubectl-datapath-agent
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "get", "delete"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kubectl-datapath-agent-managers
  namespace: kubectl-datapath-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubectl-datapath-agent-manager
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: kubectl-datapath-users
```

Where `ValidatingAdmissionPolicy` is enabled, bind a policy to this dedicated
namespace so Pod creation permission cannot be used to request arbitrary
privileged workloads. Replace the example digest with the exact agent image
approved by the platform team; update the policy when upgrading the agent:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kubectl-datapath-agent-only
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: >
        has(object.metadata.labels) &&
        object.metadata.labels['app.kubernetes.io/managed-by'] == 'kubectl-datapath' &&
        object.metadata.labels['app.kubernetes.io/component'] == 'agent' &&
        object.spec.hostNetwork &&
        object.spec.hostPID &&
        object.spec.automountServiceAccountToken == false &&
        object.spec.containers.size() == 1 &&
        object.spec.containers.all(c,
          c.image.matches('^ghcr[.]io/srodi/kubectl-datapath@sha256:[0-9a-f]{64}$') &&
          c.command == ['/kubectl-datapath'] &&
          has(c.securityContext) &&
          c.securityContext.privileged == true &&
          c.volumeMounts.size() == 2 &&
          c.volumeMounts.all(m,
            m.readOnly &&
            m.mountPath in ['/host/proc', '/host/sys/fs/cgroup'])) &&
        object.spec.volumes.size() == 2 &&
        object.spec.volumes.all(v,
          has(v.hostPath) &&
          v.hostPath.path in ['/proc', '/sys/fs/cgroup'] &&
          v.hostPath.type == 'Directory')
      message: "Only the approved kubectl-datapath agent Pod is allowed"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: kubectl-datapath-agent-only
spec:
  policyName: kubectl-datapath-agent-only
  validationActions: ["Deny"]
  matchResources:
    namespaceSelector:
      matchLabels:
        kubectl-datapath-agent: "true"
```

Run traces with:

```sh
kubectl datapath trace pod default/frontend \
  --to service/default/backend \
  --agent-namespace kubectl-datapath-agent
```

## Out of scope

The project does not claim to isolate an agent from its node, provide packet
payload confidentiality, replace Kubernetes audit logging, or prove that a
specific CNI or policy program dropped a packet.
