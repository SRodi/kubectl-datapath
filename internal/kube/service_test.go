package kube

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveServiceTraceIncludesDualStackFrontendsAndReadyBackends(t *testing.T) {
	port := int32(8080)
	portName := "http"
	ready := true
	notReady := false
	source := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "client", UID: "source"},
		Spec:       corev1.PodSpec{NodeName: "worker-a"},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "fd00:10::10"}}},
	}

	backend := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "api-abc", UID: "backend"},
		Spec:       corev1.PodSpec{NodeName: "worker-b"},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "fd00:10::20"}}},
	}
	clientset := fake.NewClientset(
		source,
		backend,
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "api"},
			Spec: corev1.ServiceSpec{
				ClusterIPs: []string{"10.96.0.10", "fd00:96::10"},
				Ports:      []corev1.ServicePort{{Name: "http", Port: 80}},
			},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo", Name: "api-v6",
				Labels: map[string]string{discoveryv1.LabelServiceName: "api"},
			},
			Ports: []discoveryv1.EndpointPort{{Name: &portName, Port: &port}},
			Endpoints: []discoveryv1.Endpoint{
				{
					Addresses:  []string{"fd00:10::20"},
					Conditions: discoveryv1.EndpointConditions{Ready: &ready},
					TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "demo", Name: "api-abc"},
				},
				{Addresses: []string{"fd00:10::99"}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
			},
		},
	)
	client := &Client{Clientset: clientset, Namespace: "demo"}
	trace, err := client.ResolveServiceTrace(context.Background(), source, "api")
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.Context.Frontends) != 2 {
		t.Fatalf("frontends = %d", len(trace.Context.Frontends))
	}
	if len(trace.Context.Backends) != 1 || trace.Context.Backends[0].Name != "api-abc" ||
		trace.Context.Backends[0].Node != "worker-b" {
		t.Fatalf("backends = %#v", trace.Context.Backends)
	}
	if len(trace.Backends) != 1 || trace.Backends[0].Name != "api-abc" {
		t.Fatalf("backend Pods = %#v", trace.Backends)
	}
}

func TestResolveServiceTraceRejectsUDPOnlyService(t *testing.T) {
	source := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "client"},
		Spec:       corev1.PodSpec{NodeName: "worker-a"},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.0.2"}}},
	}
	client := &Client{
		Namespace: "demo",
		Clientset: fake.NewClientset(source, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "dns"},
			Spec: corev1.ServiceSpec{
				ClusterIP:  "10.96.0.53",
				ClusterIPs: []string{"10.96.0.53"},
				Ports: []corev1.ServicePort{{
					Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP,
				}},
			},
		}),
	}
	if _, err := client.ResolveServiceTrace(context.Background(), source, "dns"); err == nil ||
		!strings.Contains(err.Error(), "UDP Service tracing is not supported") {
		t.Fatalf("error = %v", err)
	}
}
