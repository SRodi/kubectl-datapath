package kube

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func (c *Client) RelevantNetworkPolicies(
	ctx context.Context,
	source *corev1.Pod,
	destinations []*corev1.Pod,
) ([]model.PolicyContext, []error) {
	podsByNamespace := make(map[string][]*corev1.Pod)
	podsByNamespace[source.Namespace] = append(podsByNamespace[source.Namespace], source)
	for _, pod := range destinations {
		podsByNamespace[pod.Namespace] = append(podsByNamespace[pod.Namespace], pod)
	}
	namespaces := make([]string, 0, len(podsByNamespace))
	for namespace := range podsByNamespace {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	var result []model.PolicyContext
	var warnings []error
	for _, namespace := range namespaces {
		policies, err := c.Clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			warnings = append(warnings, fmt.Errorf("list NetworkPolicies in %s: %w", namespace, err))
			continue
		}
		for _, policy := range policies.Items {
			selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
			if err != nil {
				warnings = append(warnings, fmt.Errorf("parse NetworkPolicy %s/%s selector: %w", namespace, policy.Name, err))
				continue
			}
			if namespace == source.Namespace && selector.Matches(labels.Set(source.Labels)) &&
				policyHasType(policy, networkingv1.PolicyTypeEgress) {
				result = append(result, model.PolicyContext{
					Namespace: namespace, Name: policy.Name, Scope: "source egress",
					Pods: []string{source.Name}, DenyAll: len(policy.Spec.Egress) == 0,
				})
			}
			var selected []string
			for _, pod := range destinations {
				if pod.Namespace == namespace && selector.Matches(labels.Set(pod.Labels)) {
					selected = append(selected, pod.Name)
				}
			}
			if len(selected) > 0 && policyHasType(policy, networkingv1.PolicyTypeIngress) {
				sort.Strings(selected)
				result = append(result, model.PolicyContext{
					Namespace: namespace, Name: policy.Name, Scope: "destination ingress",
					Pods: selected, DenyAll: len(policy.Spec.Ingress) == 0,
				})
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].Namespace + "/" + result[i].Name + "/" + result[i].Scope
		right := result[j].Namespace + "/" + result[j].Name + "/" + result[j].Scope
		return left < right
	})
	return result, warnings
}

func policyHasType(policy networkingv1.NetworkPolicy, expected networkingv1.PolicyType) bool {
	for _, policyType := range policy.Spec.PolicyTypes {
		if policyType == expected {
			return true
		}
	}
	if expected == networkingv1.PolicyTypeIngress && len(policy.Spec.PolicyTypes) == 0 {
		return true
	}
	if expected == networkingv1.PolicyTypeEgress && len(policy.Spec.PolicyTypes) == 0 && policy.Spec.Egress != nil {
		return true
	}
	return false
}
