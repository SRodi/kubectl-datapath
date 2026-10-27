package enrich

import (
	"context"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestApplyOnlyUsesExactAddressMatches(t *testing.T) {
	index := New()
	address := netip.MustParseAddr("10.0.0.2")
	index.AddEndpoint(model.Endpoint{Kind: model.EndpointIP, Name: "pod=default/backend", Address: address})
	observation := index.Apply(model.Observation{DstAddr: address})
	if observation.DstLabel != "pod=default/backend" {
		t.Fatalf("label = %q", observation.DstLabel)
	}
}

func TestBuildNamespacesAvoidsClusterWideInference(t *testing.T) {
	client := fake.NewClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.0.0.2"}}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
			Spec:       corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.10"}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "unrelated"},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.0.9.9"}}},
		},
	)
	index, warnings := BuildNamespaces(context.Background(), client, "demo")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	got := index.Apply(model.Observation{
		SrcAddr: netip.MustParseAddr("10.0.0.2"),
		DstAddr: netip.MustParseAddr("10.96.0.10"),
	})
	if got.SrcLabel != "pod=demo/backend" || got.DstLabel != "svc=demo/backend" {
		t.Fatalf("labels = %q, %q", got.SrcLabel, got.DstLabel)
	}
	if got.SrcEndpoint == nil || got.SrcEndpoint.Kind != model.EndpointPod ||
		got.DstEndpoint == nil || got.DstEndpoint.Kind != model.EndpointService {
		t.Fatalf("typed endpoints = %#v, %#v", got.SrcEndpoint, got.DstEndpoint)
	}
	unrelated := index.Apply(model.Observation{SrcAddr: netip.MustParseAddr("10.0.9.9")})
	if unrelated.SrcLabel != "" {
		t.Fatalf("unexpected cross-namespace label %q", unrelated.SrcLabel)
	}
}

func TestMergeAddsSupportingNamespaceEndpoints(t *testing.T) {
	index := New()
	dns := New()
	address := netip.MustParseAddr("10.96.0.10")
	dns.AddEndpoint(model.Endpoint{
		Kind: model.EndpointService, Namespace: "kube-system", Name: "kube-dns", Address: address,
	})
	index.Merge(dns)
	got := index.Apply(model.Observation{DstAddr: address, DstPort: 53})
	if got.DstEndpoint == nil || got.DstEndpoint.Name != "kube-dns" {
		t.Fatalf("endpoint = %#v", got.DstEndpoint)
	}
}
