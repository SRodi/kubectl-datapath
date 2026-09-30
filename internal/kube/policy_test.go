package kube

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRelevantNetworkPoliciesSeparatesConfigurationFromEvidence(t *testing.T) {
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
	client := &Client{Clientset: fake.NewClientset(
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "deny-all-backend"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "frontend-egress"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
			},
		},
	)}
	policies, warnings := client.RelevantNetworkPolicies(context.Background(), source, []*corev1.Pod{destination})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if len(policies) != 2 {
		t.Fatalf("policies = %#v", policies)
	}
	if policies[0].Name != "deny-all-backend" || policies[0].Scope != "destination ingress" || !policies[0].DenyAll {
		t.Fatalf("destination policy = %#v", policies[0])
	}
	if policies[1].Name != "frontend-egress" || policies[1].Scope != "source egress" || policies[1].DenyAll {
		t.Fatalf("source policy = %#v", policies[1])
	}
}
