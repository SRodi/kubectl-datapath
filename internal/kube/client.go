package kube

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	REST      *rest.Config
	Clientset kubernetes.Interface
	Namespace string
}

type DestinationKind string

const (
	DestinationPod     DestinationKind = "pod"
	DestinationService DestinationKind = "service"
)

type Destination struct {
	Kind      DestinationKind
	Reference string
}

func NewClient(kubeconfig, contextName, namespace string) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	if namespace != "" {
		overrides.Context.Namespace = namespace
	}
	configLoader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	config, err := configLoader.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	resolvedNamespace, _, err := configLoader.Namespace()
	if err != nil {
		return nil, fmt.Errorf("resolve namespace: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return &Client{REST: config, Clientset: clientset, Namespace: resolvedNamespace}, nil
}

func (c *Client) ResolvePod(ctx context.Context, reference string) (*corev1.Pod, error) {
	namespace, name, err := splitReference(reference, c.Namespace)
	if err != nil {
		return nil, err
	}
	pod, err := c.Clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get Pod %s/%s: %w", namespace, name, err)
	}
	if pod.Spec.NodeName == "" {
		return nil, fmt.Errorf("Pod %s/%s is not scheduled", namespace, name)
	}
	if len(pod.Status.PodIPs) == 0 {
		return nil, fmt.Errorf("Pod %s/%s has no IP address", namespace, name)
	}
	return pod, nil
}

func (c *Client) NodeInternalAddress(ctx context.Context, name string) (netip.Addr, error) {
	node, err := c.Clientset.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return netip.Addr{}, fmt.Errorf("get Node %s: %w", name, err)
	}
	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		parsed, err := netip.ParseAddr(address.Address)
		if err == nil {
			return parsed, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("Node %s has no valid InternalIP", name)
}

func (c *Client) ResolveDestination(ctx context.Context, reference, defaultNamespace string) (Destination, error) {
	for _, typed := range []struct {
		prefix string
		kind   DestinationKind
	}{
		{prefix: "pod/", kind: DestinationPod},
		{prefix: "service/", kind: DestinationService},
		{prefix: "svc/", kind: DestinationService},
	} {
		if strings.HasPrefix(reference, typed.prefix) {
			normalized, err := normalizeReference(strings.TrimPrefix(reference, typed.prefix), defaultNamespace)
			if err != nil {
				return Destination{}, err
			}
			return Destination{Kind: typed.kind, Reference: normalized}, nil
		}
	}

	normalized, err := normalizeReference(reference, defaultNamespace)
	if err != nil {
		return Destination{}, err
	}
	namespace, name, _ := splitReference(normalized, defaultNamespace)
	_, podErr := c.Clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	_, serviceErr := c.Clientset.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	podFound := podErr == nil
	serviceFound := serviceErr == nil
	if podErr != nil && !apierrors.IsNotFound(podErr) {
		return Destination{}, fmt.Errorf("resolve destination Pod %s: %w", normalized, podErr)
	}
	if serviceErr != nil && !apierrors.IsNotFound(serviceErr) {
		return Destination{}, fmt.Errorf("resolve destination Service %s: %w", normalized, serviceErr)
	}
	switch {
	case podFound && serviceFound:
		return Destination{}, fmt.Errorf(
			"destination %q is ambiguous: both Pod and Service %s exist; use pod/%s or service/%s",
			reference, normalized, normalized, normalized,
		)
	case podFound:
		return Destination{Kind: DestinationPod, Reference: normalized}, nil
	case serviceFound:
		return Destination{Kind: DestinationService, Reference: normalized}, nil
	default:
		return Destination{}, fmt.Errorf("destination %q does not match a Pod or Service in namespace %s", reference, namespace)
	}
}

func normalizeReference(reference, defaultNamespace string) (string, error) {
	namespace, name, err := splitReference(reference, defaultNamespace)
	if err != nil {
		return "", err
	}
	return namespace + "/" + name, nil
}

func splitReference(reference, defaultNamespace string) (string, string, error) {
	parts := strings.Split(reference, "/")
	switch len(parts) {
	case 1:
		if parts[0] == "" {
			return "", "", fmt.Errorf("empty resource reference")
		}
		return defaultNamespace, parts[0], nil
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("invalid resource reference %q", reference)
		}
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("resource reference must be [namespace/]name, got %q", reference)
	}
}
