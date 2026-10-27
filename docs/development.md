# Development

## Build and test

The generated BPF objects are checked in, so `make build` works on supported
Go development hosts, including macOS. `make check` runs the unit tests and
`go vet`.

Regenerate the BPF objects through the pinned Linux toolchain container:

```sh
make generate
```

This requires Docker with support for running `linux/arm64` images. Docker
Desktop provides this on macOS; Linux hosts may need QEMU binfmt support. The
image pins the Clang 19.1.7 environment used for the checked-in objects.

On Linux with BPF privileges, also run
`sudo env DATAPATH_BPF_TEST=1 go test ./internal/capture/tcx -run TestPacketDiagnosticsBPF`
to exercise parser rejection, filtering, successful emission, ring-buffer
exhaustion, and unchanged forwarding verdicts without attaching to interfaces.

## End-to-end tests

Each target creates a disposable three-node Kind cluster, builds and loads the
agent image, deploys a cross-node frontend/backend workload, and checks allowed
traffic plus ingress- and egress-policy scenarios. CI uses the same runner.

```sh
make e2e-kindnet
make e2e-flannel
make e2e-cilium
make e2e-calico
```

`make e2e-all` runs all four in parallel. Cilium and Calico must enforce
NetworkPolicy. Kindnet and Flannel detect enforcement from the ingress scenario
and apply the same expectation to the egress-policy refresh check.

Every target also checks two Service misconfigurations
(`deploy/e2e/service-misconfig.yaml`):

- **Wrong `targetPort`:** the trace shows the connect intent, the translated
  SYN at the backend Pod boundary, and the backend's reset. Translation and
  delivery to the Pod boundary worked; the failure is above the datapath.
- **Selector matching no Pods:** the trace refuses to start because the Service
  has no ready EndpointSlice backends, and emits no evidence.

The Calico target patches the pinned manifest to IP-in-IP `CrossSubnet`
(`CALICO_IPIP_MODE`), so same-subnet Kind nodes route natively and node
transit is asserted. Calico's default `Always` IP-in-IP mode is not decoded.

### Netkit

On an existing netkit-cni cluster with its Python HTTP test workloads
(`netkit-test/same-a`, `same-b`, and `cross-b`), build and load the agent image
on every involved node, then run:

```sh
E2E_IMAGE=kubectl-datapath:e2e make e2e-netkit
```

This checks same-node and cross-node requests, both hook directions at each Pod
boundary, native transit, detected L3 netkit and `nk-vrf` table 100, final
diagnostic counters, and replay metadata. It does not install a CNI or replace
workloads. Override `E2E_NETKIT_NAMESPACE`, `E2E_NETKIT_SOURCE`,
`E2E_NETKIT_SAME_NODE`, `E2E_NETKIT_CROSS_NODE`, and `E2E_NETKIT_PORT` for
equivalent workloads. `E2E_ARTIFACT_DIR` selects the recording directory.

## Images and releases

CI publishes immutable images such as
`ghcr.io/srodi/kubectl-datapath:sha-<commit>`. For a private package, create
the pull secret in the agent namespace without putting credentials in a file:

```sh
GHCR_USERNAME=... GHCR_TOKEN=... make image-pull-secret
```

Release binaries default to the matching immutable semver agent image; the
`version` command prints both values. Tag workflows publish Linux and macOS
binaries, checksums, multi-architecture agent images, and a rendered
`datapath.yaml` Krew manifest as release assets, only after the unit and E2E
jobs pass.

## Krew packaging

Test the packaging and installation flow locally without publishing:

```sh
make krew-local-install
kubectl datapath --help
make krew-local-reinstall # rebuild and replace after code changes
make krew-local-uninstall
```

The install target builds GoReleaser snapshot archives, renders a
checksum-matched manifest, installs the archive for the current OS and
architecture, and runs `kubectl datapath version`. It refuses to reuse an
existing plugin so stale binaries cannot pass the smoke test; use the reinstall
target after code changes.

## Diagrams

Diagrams are generated from the Mermaid files in `docs/diagrams`:

```sh
make architecture-diagrams
make check-architecture-diagrams
```

Commit both the `.mmd` source and the generated `.svg`. CI rejects stale SVGs.
