package kube

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveDestinationInfersUniqueResource(t *testing.T) {
	client := &Client{
		Clientset: fake.NewClientset(
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "worker"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "api"}},
		),
	}
	pod, err := client.ResolveDestination(context.Background(), "worker", "demo")
	if err != nil || pod.Kind != DestinationPod || pod.Reference != "demo/worker" {
		t.Fatalf("Pod destination = %#v, err=%v", pod, err)
	}
	service, err := client.ResolveDestination(context.Background(), "api", "demo")
	if err != nil || service.Kind != DestinationService || service.Reference != "demo/api" {
		t.Fatalf("Service destination = %#v, err=%v", service, err)
	}
}

func TestResolveDestinationRejectsAmbiguousName(t *testing.T) {
	client := &Client{
		Clientset: fake.NewClientset(
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"}},
		),
	}
	_, err := client.ResolveDestination(context.Background(), "backend", "demo")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") ||
		!strings.Contains(err.Error(), "pod/demo/backend") ||
		!strings.Contains(err.Error(), "service/demo/backend") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveDestinationAcceptsExplicitTypes(t *testing.T) {
	client := &Client{Clientset: fake.NewClientset()}
	for input, expected := range map[string]Destination{
		"pod/backend":           {Kind: DestinationPod, Reference: "demo/backend"},
		"service/backend":       {Kind: DestinationService, Reference: "demo/backend"},
		"svc/other/backend":     {Kind: DestinationService, Reference: "other/backend"},
		"pod/other/backend-abc": {Kind: DestinationPod, Reference: "other/backend-abc"},
	} {
		actual, err := client.ResolveDestination(context.Background(), input, "demo")
		if err != nil || actual != expected {
			t.Fatalf("%q = %#v, err=%v; want %#v", input, actual, err, expected)
		}
	}
}
