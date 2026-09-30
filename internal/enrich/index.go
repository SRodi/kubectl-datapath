package enrich

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

type Index struct {
	endpoints map[netip.Addr]model.Endpoint
}

func New() *Index {
	return &Index{endpoints: make(map[netip.Addr]model.Endpoint)}
}

func BuildNamespaces(ctx context.Context, client kubernetes.Interface, namespaces ...string) (*Index, []error) {
	index := New()
	unique := make(map[string]struct{}, len(namespaces))
	for _, namespace := range namespaces {
		if namespace != "" {
			unique[namespace] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(unique))
	for namespace := range unique {
		ordered = append(ordered, namespace)
	}
	sort.Strings(ordered)

	var warnings []error
	for _, namespace := range ordered {
		pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			warnings = append(warnings, fmt.Errorf("list Pods in %s: %w", namespace, err))
		} else {
			for _, pod := range pods.Items {
				for _, podIP := range pod.Status.PodIPs {
					address, err := netip.ParseAddr(podIP.IP)
					if err == nil {
						index.AddEndpoint(model.Endpoint{
							Kind: model.EndpointPod, Namespace: pod.Namespace, Name: pod.Name,
							Node: pod.Spec.NodeName, Address: address,
						})
					}
				}
			}
		}
		services, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			warnings = append(warnings, fmt.Errorf("list Services in %s: %w", namespace, err))
		} else {
			for _, service := range services.Items {
				for _, clusterIP := range service.Spec.ClusterIPs {
					address, err := netip.ParseAddr(clusterIP)
					if err == nil {
						index.AddEndpoint(model.Endpoint{
							Kind: model.EndpointService, Namespace: service.Namespace, Name: service.Name, Address: address,
						})
					}
				}
			}
		}
	}
	return index, warnings
}

func (i *Index) Add(address netip.Addr, label string) {
	if address.IsValid() {
		i.endpoints[address] = model.Endpoint{Kind: model.EndpointIP, Name: label, Address: address}
	}
}

func (i *Index) AddEndpoint(endpoint model.Endpoint) {
	if endpoint.Address.IsValid() {
		i.endpoints[endpoint.Address] = endpoint
	}
}

func (i *Index) Merge(other *Index) {
	if other == nil {
		return
	}
	for address, endpoint := range other.endpoints {
		i.endpoints[address] = endpoint
	}
}

func (i *Index) Apply(observation model.Observation) model.Observation {
	if endpoint, ok := i.endpoints[observation.SrcAddr]; ok {
		endpoint.Port = observation.SrcPort
		observation.SrcEndpoint = &endpoint
		observation.SrcLabel = endpointLabel(endpoint)
	}
	if endpoint, ok := i.endpoints[observation.DstAddr]; ok {
		endpoint.Port = observation.DstPort
		observation.DstEndpoint = &endpoint
		observation.DstLabel = endpointLabel(endpoint)
	}
	return observation
}

func endpointLabel(endpoint model.Endpoint) string {
	switch endpoint.Kind {
	case model.EndpointPod:
		return "pod=" + endpoint.Namespace + "/" + endpoint.Name
	case model.EndpointService:
		return "svc=" + endpoint.Namespace + "/" + endpoint.Name
	default:
		return endpoint.Name
	}
}
