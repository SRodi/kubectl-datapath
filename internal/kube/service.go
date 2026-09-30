package kube

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

type ServiceTrace struct {
	Context  model.TraceContext
	Backends []*corev1.Pod
}

func (c *Client) ResolveServiceTrace(ctx context.Context, source *corev1.Pod, reference string) (*ServiceTrace, error) {
	namespace, name, err := splitReference(reference, source.Namespace)
	if err != nil {
		return nil, fmt.Errorf("invalid Service reference: %w", err)
	}
	service, err := c.Clientset.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get Service %s/%s: %w", namespace, name, err)
	}
	if service.Spec.ClusterIP == corev1.ClusterIPNone || len(service.Spec.ClusterIPs) == 0 {
		return nil, fmt.Errorf("Service %s/%s has no ClusterIP frontend", namespace, name)
	}

	trace := &ServiceTrace{Context: model.TraceContext{
		Source:  podEndpoint(source),
		Service: &model.Endpoint{Kind: model.EndpointService, Namespace: namespace, Name: name},
	}}
	tcpPorts := make(map[string]bool)
	for _, clusterIP := range service.Spec.ClusterIPs {
		address, err := netip.ParseAddr(clusterIP)
		if err != nil {
			continue
		}
		for _, port := range service.Spec.Ports {
			if port.Protocol != "" && port.Protocol != corev1.ProtocolTCP {
				continue
			}
			tcpPorts[port.Name] = true
			trace.Context.Frontends = append(trace.Context.Frontends, model.Endpoint{
				Kind: model.EndpointService, Namespace: namespace, Name: name,
				Address: address, Port: uint16(port.Port), PortName: port.Name,
			})
		}
	}
	if len(trace.Context.Frontends) == 0 {
		return nil, fmt.Errorf("Service %s/%s has no TCP ports; UDP Service tracing is not supported", namespace, name)
	}

	slices, err := c.Clientset.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + name,
	})
	if err != nil {
		return nil, fmt.Errorf("list EndpointSlices for Service %s/%s: %w", namespace, name, err)
	}
	pods := make(map[string]*corev1.Pod)
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			var pod *corev1.Pod
			if endpoint.TargetRef != nil && endpoint.TargetRef.Kind == "Pod" {
				podNamespace := endpoint.TargetRef.Namespace
				if podNamespace == "" {
					podNamespace = namespace
				}
				key := podNamespace + "/" + endpoint.TargetRef.Name
				pod = pods[key]
				if pod == nil {
					pod, err = c.ResolvePod(ctx, key)
					if err != nil {
						return nil, fmt.Errorf("resolve Service backend %s: %w", key, err)
					}
					pods[key] = pod
				}
			}
			for _, value := range endpoint.Addresses {
				address, err := netip.ParseAddr(value)
				if err != nil {
					continue
				}
				for _, port := range slice.Ports {
					if port.Port == nil {
						continue
					}
					if port.Protocol != nil && *port.Protocol != corev1.ProtocolTCP {
						continue
					}
					if port.Name != nil && len(tcpPorts) > 0 && !tcpPorts[*port.Name] {
						continue
					}
					backend := model.Endpoint{Kind: model.EndpointIP, Address: address, Port: uint16(*port.Port)}
					if port.Name != nil {
						backend.PortName = *port.Name
					}
					if pod != nil {
						backend.Kind = model.EndpointPod
						backend.Namespace = pod.Namespace
						backend.Name = pod.Name
						backend.Node = pod.Spec.NodeName
					}
					trace.Context.Backends = append(trace.Context.Backends, backend)
				}
			}
		}
	}
	for _, pod := range pods {
		trace.Backends = append(trace.Backends, pod)
	}
	sort.Slice(trace.Backends, func(i, j int) bool {
		return trace.Backends[i].Namespace+"/"+trace.Backends[i].Name <
			trace.Backends[j].Namespace+"/"+trace.Backends[j].Name
	})
	if len(trace.Context.Backends) == 0 {
		return nil, fmt.Errorf("Service %s/%s has no ready EndpointSlice backends", namespace, name)
	}
	return trace, nil
}

func podEndpoint(pod *corev1.Pod) model.Endpoint {
	endpoint := model.Endpoint{
		Kind: model.EndpointPod, Namespace: pod.Namespace, Name: pod.Name, Node: pod.Spec.NodeName,
	}
	if len(pod.Status.PodIPs) > 0 {
		endpoint.Address, _ = netip.ParseAddr(pod.Status.PodIPs[0].IP)
	}
	return endpoint
}
