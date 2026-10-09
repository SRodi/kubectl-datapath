BINARY := bin/kubectl-datapath
GIT_SHA ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo dev)
IMAGE ?= kubectl-datapath:e2e
REGISTRY_IMAGE ?= ghcr.io/srodi/kubectl-datapath:sha-$(GIT_SHA)
BPF_GENERATOR_IMAGE ?= quay.io/cilium/cilium-builder:acc6214750a75465edd69451692572f35efba34d@sha256:2b069f0b1296ae760c70f2fc533faf0d851b01c7b6fa0925992cef862d31ef92
BPF_GENERATOR_PLATFORM ?= linux/arm64
E2E_CLUSTER ?= kubectl-datapath-e2e
KIND_VERSION ?= v0.33.0
CILIUM_VERSION ?= 1.20.2
CALICO_VERSION ?= v3.32.2
FLANNEL_VERSION ?= v0.28.9
FLANNEL_MANIFEST_SHA256 ?= 1c06a15a771009c263bdb1f51c928af46f7606fe969f3963652167938d536aaa
CALICO_MANIFEST_SHA256 ?= a8c828a06a87c629a282ebbc424895b77f3a030251993e41ea400a743675bb02
CNI_PLUGINS_VERSION ?= v1.9.1
CNI_PLUGINS_ARCH ?= amd64
CNI_PLUGINS_SHA256 ?= b98f74a0f8522f0a83867178729c1aa70f2158f90c45a2ca8fa791db1c76b303
AGENT_NAMESPACE ?= kube-system
IMAGE_PULL_SECRET ?= kubectl-datapath-ghcr
REGISTRY_SERVER ?= ghcr.io
GHCR_USERNAME ?= $(shell gh api user --jq .login 2>/dev/null)
GHCR_TOKEN ?= $(shell gh auth token 2>/dev/null)
GORELEASER_VERSION ?= v2.18.2
KREW_LOCAL_MANIFEST ?= dist/datapath.yaml

.PHONY: generate generate-bpf build test vet fmt check clean ci-unit \
	architecture-diagrams check-architecture-diagrams \
	docker-build docker-push print-registry-image kind-load image-pull-secret \
	kind-kindnet-up kind-flannel-up kind-cilium-up kind-calico-up kind-down \
	e2e-kindnet e2e-flannel e2e-cilium e2e-calico e2e-netkit e2e-all \
	krew-local-package krew-local-install krew-local-reinstall krew-local-uninstall

generate:
	go generate ./...

generate-bpf:
	docker run --rm --platform $(BPF_GENERATOR_PLATFORM) \
		-e HOST_UID=$(shell id -u) -e HOST_GID=$(shell id -g) \
		-v "$(CURDIR):/src" -w /src $(BPF_GENERATOR_IMAGE) \
		sh /src/scripts/generate-bpf-container.sh

build:
	go build -o $(BINARY) ./cmd/kubectl-datapath

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './internal/capture/tcx/bpf_*')

check: test vet
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './internal/capture/tcx/bpf_*'))"

ci-unit: generate-bpf
	git diff --exit-code
	$(MAKE) check-architecture-diagrams
	$(MAKE) check
	$(MAKE) build
	./bin/kubectl-datapath replay --no-tui testdata/tcp-success.ndjson >/dev/null
	./bin/kubectl-datapath replay --no-tui testdata/service-kube-proxy.ndjson >/dev/null
	./bin/kubectl-datapath replay --no-tui testdata/service-cilium-socket-lb.ndjson >/dev/null

clean:
	rm -f $(BINARY)
	rm -rf dist

architecture-diagrams:
	./scripts/render-architecture-diagrams.sh

check-architecture-diagrams:
	./scripts/render-architecture-diagrams.sh --check

krew-local-package:
	go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) \
		release --snapshot --clean --skip=publish
	@set -eu; \
	os=$$(go env GOOS); \
	arch=$$(go env GOARCH); \
	set -- dist/kubectl-datapath_*_$${os}_$${arch}.tar.gz; \
	[ "$$#" -eq 1 ] && [ -f "$$1" ] || { echo "error: host archive not found" >&2; exit 1; }; \
	archive=$${1##*/}; \
	version=$${archive#kubectl-datapath_}; \
	version=$${version%_$${os}_$${arch}.tar.gz}; \
	./scripts/render-krew-manifest.sh "v$$version" dist/checksums.txt $(KREW_LOCAL_MANIFEST); \
	echo "local Krew manifest: $(KREW_LOCAL_MANIFEST)"; \
	echo "local Krew archive:  dist/$$archive"

krew-local-install: krew-local-package
	@kubectl krew version >/dev/null
	@if kubectl krew list | grep -Eq '(^|/)datapath$$'; then \
		echo "error: datapath is already installed; run 'make krew-local-reinstall'" >&2; \
		exit 1; \
	fi
	@set -eu; \
	os=$$(go env GOOS); \
	arch=$$(go env GOARCH); \
	set -- dist/kubectl-datapath_*_$${os}_$${arch}.tar.gz; \
	[ "$$#" -eq 1 ] && [ -f "$$1" ] || { echo "error: host archive not found" >&2; exit 1; }; \
	kubectl krew install --manifest=$(KREW_LOCAL_MANIFEST) --archive="$$1"
	kubectl datapath version

krew-local-reinstall:
	-kubectl krew uninstall datapath
	$(MAKE) krew-local-install

krew-local-uninstall:
	kubectl krew uninstall datapath

docker-build:
	docker build -t $(IMAGE) .

docker-push:
	docker build -t $(REGISTRY_IMAGE) .
	docker push $(REGISTRY_IMAGE)

print-registry-image:
	@echo $(REGISTRY_IMAGE)

kind-load: docker-build
	kind load docker-image $(IMAGE) --name $(E2E_CLUSTER)

image-pull-secret:
	@test -n "$(GHCR_USERNAME)" || (echo "error: set GHCR_USERNAME or authenticate gh" >&2; exit 1)
	@test -n "$(GHCR_TOKEN)" || (echo "error: set GHCR_TOKEN or authenticate gh" >&2; exit 1)
	@kubectl get namespace $(AGENT_NAMESPACE) >/dev/null
	@kubectl -n $(AGENT_NAMESPACE) create secret docker-registry $(IMAGE_PULL_SECRET) \
		--docker-server="$(REGISTRY_SERVER)" \
		--docker-username="$(GHCR_USERNAME)" \
		--docker-password="$(GHCR_TOKEN)" \
		--dry-run=client -o yaml | kubectl apply -f -

kind-kindnet-up:
	kind create cluster --name $(E2E_CLUSTER) --config deploy/e2e/kind-default.yaml

kind-flannel-up:
	kind create cluster --name $(E2E_CLUSTER) --config deploy/e2e/kind-no-cni.yaml
	@set -e; archive=$$(mktemp); \
	trap 'rm -f "$$archive"' EXIT; \
	curl -fsSL "https://github.com/containernetworking/plugins/releases/download/$(CNI_PLUGINS_VERSION)/cni-plugins-linux-$(CNI_PLUGINS_ARCH)-$(CNI_PLUGINS_VERSION).tgz" -o "$$archive"; \
	echo "$(CNI_PLUGINS_SHA256)  $$archive" | sha256sum -c -; \
	for node in $$(kind get nodes --name $(E2E_CLUSTER)); do \
		docker exec "$$node" mkdir -p /opt/cni/bin; \
		docker exec -i "$$node" tar -C /opt/cni/bin -xzf - < "$$archive"; \
	done
	@set -e; manifest=$$(mktemp); \
	trap 'rm -f "$$manifest"' EXIT; \
	curl -fsSL "https://github.com/flannel-io/flannel/releases/download/$(FLANNEL_VERSION)/kube-flannel.yml" -o "$$manifest"; \
	echo "$(FLANNEL_MANIFEST_SHA256)  $$manifest" | sha256sum -c -; \
	kubectl apply -f "$$manifest"
	kubectl -n kube-flannel rollout status daemonset/kube-flannel-ds --timeout=300s
	kubectl wait --for=condition=Ready nodes --all --timeout=300s

kind-cilium-up:
	kind create cluster --name $(E2E_CLUSTER) --config deploy/e2e/kind-cilium.yaml
	cilium install --context kind-$(E2E_CLUSTER) --version $(CILIUM_VERSION) \
		--set kubeProxyReplacement=true \
		--set routingMode=tunnel \
		--set tunnelProtocol=vxlan
	cilium status --context kind-$(E2E_CLUSTER) --wait --wait-duration=5m
	kubectl wait --for=condition=Ready nodes --all --timeout=300s

kind-calico-up:
	kind create cluster --name $(E2E_CLUSTER) --config deploy/e2e/kind-calico.yaml
	@set -e; manifest=$$(mktemp); \
	trap 'rm -f "$$manifest"' EXIT; \
	curl -fsSL "https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests/calico.yaml" -o "$$manifest"; \
	echo "$(CALICO_MANIFEST_SHA256)  $$manifest" | sha256sum -c -; \
	kubectl apply -f "$$manifest"
	kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
	kubectl -n kube-system rollout status deployment/calico-kube-controllers --timeout=300s
	kubectl wait --for=condition=Ready nodes --all --timeout=300s

kind-down:
	kind delete cluster --name $(E2E_CLUSTER)

e2e-kindnet:
	CNI=kindnet ./scripts/e2e-test.sh

e2e-flannel:
	CNI=flannel ./scripts/e2e-test.sh

e2e-cilium:
	CNI=cilium ./scripts/e2e-test.sh

e2e-calico:
	CNI=calico ./scripts/e2e-test.sh

e2e-netkit:
	bash ./scripts/e2e-netkit.sh

e2e-all: e2e-kindnet e2e-flannel e2e-cilium e2e-calico

label-nodes:
	kubectl label no kubectl-datapath-e2e-worker datapath.e2e/role=source --overwrite
	kubectl label no kubectl-datapath-e2e-worker2 datapath.e2e/role=destination --overwrite
