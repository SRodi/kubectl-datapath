package cli

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/SRodi/kubectl-datapath/internal/kube"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestPolicyContextStreamEmitsPolicyChanges(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	client := &kube.Client{Clientset: clientset}
	source := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "frontend", Labels: map[string]string{"app": "frontend"},
		},
	}
	destination := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "backend", Labels: map[string]string{"app": "backend"},
		},
	}
	command := &cobra.Command{}
	command.SetErr(&bytes.Buffer{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := policyContextStream(
		command, ctx, client, "session", model.TraceContext{Source: model.Endpoint{Name: "frontend"}},
		source, []*corev1.Pod{destination}, 5*time.Millisecond,
	)

	_, err := clientset.NetworkingV1().NetworkPolicies("demo").Create(
		ctx,
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "deny-all-frontend"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case observation := <-stream.Observations:
		if observation.Kind != model.KindTraceContext || observation.Trace == nil ||
			len(observation.Trace.Policies) != 1 ||
			observation.Trace.Policies[0].Name != "deny-all-frontend" ||
			!observation.Trace.Policies[0].DenyAll {
			t.Fatalf("policy update = %#v", observation)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for policy context update")
	}
}

func TestUniquePodsDeduplicatesEndpointPorts(t *testing.T) {
	first := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		UID: "first", Namespace: "kube-system", Name: "coredns-a",
	}}
	second := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		UID: "second", Namespace: "kube-system", Name: "coredns-b",
	}}
	got := uniquePods([]*corev1.Pod{first, first, second, first, second})
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("unique Pods = %#v", got)
	}
}

func TestNodeAgentPlansGroupAttachmentsByNode(t *testing.T) {
	source := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "source", Name: "frontend"},
		Spec:       corev1.PodSpec{NodeName: "worker-a"},
	}

	backend := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "backend", Name: "backend"},
		Spec:       corev1.PodSpec{NodeName: "worker-b"},
	}
	dnsOne := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "dns-one", Name: "coredns-a"},
		Spec:       corev1.PodSpec{NodeName: "worker-b"},
	}
	dnsTwo := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "dns-two", Name: "coredns-b"},
		Spec:       corev1.PodSpec{NodeName: "worker-b"},
	}
	plans := make(nodeAgentPlans)
	plans.addPod(source, "source", "source", true, nil)
	plans.addPod(backend, "backend-1", "backend", false, nil)
	plans.addPod(dnsOne, "dns-1", "dns", false, nil)
	plans.addPod(dnsTwo, "dns-2", "dns", false, nil)
	plans.addTransit(
		"worker-a", "192.0.2.20", "transit-source-worker-b", "transit-source",
		[]string{"10.244.0.5", "10.244.1.8"},
	)
	plans.addTransit(
		"worker-b", "192.0.2.10", "transit-destination-worker-b", "transit-destination",
		[]string{"10.244.0.5", "10.244.1.8"},
	)

	if len(plans) != 2 {
		t.Fatalf("node plans = %#v", plans)
	}
	if len(plans["worker-a"]) != 2 || len(plans["worker-b"]) != 4 {
		t.Fatalf("attachment counts = source %d destination %d",
			len(plans["worker-a"]), len(plans["worker-b"]))
	}
	if !plans["worker-a"][0].CaptureConnect ||
		plans["worker-a"][1].Side != "transit-source" ||
		plans["worker-b"][3].Side != "transit-destination" {
		t.Fatalf("plans = %#v", plans)
	}
}

func TestEndpointSignatureIsOrderIndependent(t *testing.T) {
	first := model.Endpoint{
		Namespace: "demo", Name: "api-a", Node: "worker-a",
		Address: netip.MustParseAddr("10.244.0.10"), Port: 8080,
	}
	second := model.Endpoint{
		Namespace: "demo", Name: "api-b", Node: "worker-b",
		Address: netip.MustParseAddr("10.244.1.10"), Port: 8080,
	}
	if endpointSignature([]model.Endpoint{first, second}) != endpointSignature([]model.Endpoint{second, first}) {
		t.Fatal("endpoint signature depends on EndpointSlice order")
	}
}
