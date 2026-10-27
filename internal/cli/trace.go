package cli

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/SRodi/kubectl-datapath/internal/enrich"
	"github.com/SRodi/kubectl-datapath/internal/kube"
	"github.com/SRodi/kubectl-datapath/internal/model"
	traceview "github.com/SRodi/kubectl-datapath/internal/trace"
	"github.com/SRodi/kubectl-datapath/internal/version"
)

func newTraceCommand() *cobra.Command {
	options := &traceOptions{}
	var destination string
	var maxBackends int
	command := &cobra.Command{Use: "trace", Short: "Trace traffic from a Pod"}
	command.PersistentFlags().StringVar(&options.kubeconfig, "kubeconfig", "", "path to kubeconfig")
	command.PersistentFlags().StringVar(&options.context, "context", "", "kubeconfig context")
	command.PersistentFlags().StringVarP(&options.namespace, "namespace", "n", "", "default target namespace")
	command.PersistentFlags().StringVar(&options.agentNamespace, "agent-namespace", "kube-system", "namespace for short-lived agent Pods")
	command.PersistentFlags().StringVar(&options.agentImage, "agent-image", version.AgentImage(), "agent image")
	command.PersistentFlags().StringVar(&options.agentImagePullSecret, "agent-image-pull-secret", "", "imagePullSecret in the agent namespace")
	command.PersistentFlags().BoolVar(&options.noTUI, "no-tui", false, "write NDJSON instead of opening the TUI")

	podCommand := &cobra.Command{
		Use:   "pod <namespace/name>",
		Short: "Trace a path from a Pod to a Pod or Service",
		Example: `  kubectl-datapath trace pod frontend --to backend
  kubectl-datapath trace pod frontend --to pod/backend-abc
  kubectl-datapath trace pod frontend --to service/backend`,
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			ctx, stop := signalContext()
			defer stop()
			client, err := kube.NewClient(options.kubeconfig, options.context, options.namespace)
			if err != nil {
				return err
			}
			source, err := client.ResolvePod(ctx, args[0])
			if err != nil {
				return err
			}
			resolved, err := client.ResolveDestination(ctx, destination, source.Namespace)
			if err != nil {
				return err
			}
			switch resolved.Kind {
			case kube.DestinationPod:
				target, err := client.ResolvePod(ctx, resolved.Reference)
				if err != nil {
					return err
				}
				return runPodPathTrace(command, ctx, client, source, target, options)
			case kube.DestinationService:
				serviceTrace, err := client.ResolveServiceTrace(ctx, source, resolved.Reference)
				if err != nil {
					return err
				}
				return runServiceTrace(command, ctx, client, source, serviceTrace, options, maxBackends)
			default:
				return fmt.Errorf("unsupported destination kind %q", resolved.Kind)
			}
		},
	}
	podCommand.Flags().StringVar(&destination, "to", "", "destination [namespace/]name, pod/..., service/..., or svc/...")
	podCommand.Flags().IntVar(&maxBackends, "max-backends", 4, "maximum ready Service backend Pods to observe")
	_ = podCommand.MarkFlagRequired("to")
	command.AddCommand(podCommand)
	return command
}

func runPodPathTrace(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	source, destination *corev1.Pod,
	options *traceOptions,
) (traceErr error) {
	if source.Namespace == destination.Namespace && source.Name == destination.Name {
		return fmt.Errorf("source and destination Pods must be different")
	}
	index := buildIndex(ctx, command.ErrOrStderr(), client, source, destination)
	sessionID, err := newSessionID()
	if err != nil {
		return err
	}
	plans := make(nodeAgentPlans)
	destinationEndpoint := podTraceEndpoint(destination)
	traceContext := model.TraceContext{
		Mode: model.TraceModePod, Source: podTraceEndpoint(source), Destination: &destinationEndpoint,
	}
	pathAddresses := endpointAddresses(traceContext.Source, destinationEndpoint)
	plans.addPod(source, "source", "source", false, pathAddresses)
	plans.addPod(destination, "destination", "destination", false, pathAddresses)
	traceContext.Policies = relevantPolicies(command, ctx, client, source, []*corev1.Pod{destination})
	if source.Spec.NodeName != destination.Spec.NodeName {
		unavailable := planTransitPair(
			command, ctx, client, sessionID, source, destination, plans,
		)
		traceContext.NodeTransit = &model.NodeTransitContext{
			SourceNode: source.Spec.NodeName, DestinationNodes: []string{destination.Spec.NodeName},
			Unavailable: unavailable,
		}
	}
	streams, err := startNodeAgents(ctx, client, options, sessionID, plans, index)
	if err != nil {
		return err
	}
	deliveryCtx, cleanup := traceStreamContext(ctx, streams)
	defer func() {
		traceErr = errors.Join(traceErr, cleanup())
	}()
	observations, errors := mergeStreams(deliveryCtx, streams...)
	observations = filterPodPathObservations(deliveryCtx, traceContext, observations)
	observations = prependTraceContext(deliveryCtx, sessionID, traceContext, observations)
	title := source.Namespace + "/" + source.Name + " → " + destination.Namespace + "/" + destination.Name
	return consume(command, ctx, title, observations, errors, options.noTUI)
}

func podTraceEndpoint(pod *corev1.Pod) model.Endpoint {
	endpoint := model.Endpoint{
		Kind: model.EndpointPod, Namespace: pod.Namespace, Name: pod.Name, Node: pod.Spec.NodeName,
	}
	if len(pod.Status.PodIPs) > 0 {
		endpoint.Address, _ = modelAddress(pod.Status.PodIPs[0].IP)
	}
	return endpoint
}

func filterPodPathObservations(
	ctx context.Context,
	traceContext model.TraceContext,
	input <-chan model.Observation,
) <-chan model.Observation {
	output := make(chan model.Observation, 1024)
	go func() {
		defer close(output)
		for observation := range input {
			if !traceview.RelevantPodPath(observation, traceContext) {
				continue
			}
			select {
			case output <- observation:
			case <-ctx.Done():
				return
			}
		}
	}()
	return output
}

func runServiceTrace(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	source *corev1.Pod,
	serviceTrace *kube.ServiceTrace,
	options *traceOptions,
	maxBackends int,
) (traceErr error) {
	serviceTrace.Context.Mode = model.TraceModeService
	if maxBackends < 0 {
		return fmt.Errorf("--max-backends cannot be negative")
	}
	backends := uniquePods(serviceTrace.Backends)
	if len(backends) > maxBackends {
		backends = backends[:maxBackends]
	}
	serviceTrace.Context.InstrumentedBackends = endpointsForPods(serviceTrace.Context.Backends, backends)
	serviceTrace.Context.BackendCoverageKnown = true
	dnsTrace, dnsWarning := client.ResolveServiceTrace(ctx, source, "kube-system/kube-dns")
	var dnsBackends []*corev1.Pod
	if dnsWarning == nil {
		serviceTrace.Context.DNSService = dnsTrace.Context.Service
		serviceTrace.Context.DNSFrontends = dnsTrace.Context.Frontends
		serviceTrace.Context.DNSBackends = dnsTrace.Context.Backends
		dnsBackends = uniquePods(dnsTrace.Backends)
	} else {
		fmt.Fprintf(command.ErrOrStderr(), "warning: DNS backend observation unavailable: %v\n", dnsWarning)
	}

	targets := append([]*corev1.Pod{source}, backends...)
	targets = append(targets, dnsBackends...)
	index := buildIndex(ctx, command.ErrOrStderr(), client, targets...)
	dnsIndex, warnings := enrich.BuildNamespaces(ctx, client.Clientset, "kube-system")
	for _, warning := range warnings {
		fmt.Fprintf(command.ErrOrStderr(), "warning: DNS metadata unavailable: %v\n", warning)
	}
	index.Merge(dnsIndex)
	for _, endpoint := range append(append([]model.Endpoint{}, serviceTrace.Context.Frontends...), serviceTrace.Context.Backends...) {
		index.AddEndpoint(endpoint)
	}
	for _, endpoint := range append(append([]model.Endpoint{}, serviceTrace.Context.DNSFrontends...), serviceTrace.Context.DNSBackends...) {
		index.AddEndpoint(endpoint)
	}
	index.AddEndpoint(serviceTrace.Context.Source)

	sessionID, err := newSessionID()
	if err != nil {
		return err
	}
	plans := make(nodeAgentPlans)
	serviceAddresses := traceFlowAddresses(serviceTrace.Context)
	plans.addPod(source, "source", "source", true, serviceAddresses)
	for i, backend := range backends {
		plans.addPod(
			backend, fmt.Sprintf("backend-%d", i+1), "backend", false,
			endpointAddresses(append(
				[]model.Endpoint{serviceTrace.Context.Source},
				endpointsForPods(serviceTrace.Context.InstrumentedBackends, []*corev1.Pod{backend})...,
			)...),
		)
	}
	for i, backend := range dnsBackends {
		plans.addPod(
			backend, fmt.Sprintf("dns-%d", i+1), "dns", false,
			endpointAddresses(append(
				[]model.Endpoint{serviceTrace.Context.Source},
				append(append([]model.Endpoint{}, serviceTrace.Context.DNSFrontends...),
					serviceTrace.Context.DNSBackends...)...,
			)...),
		)
	}
	transitTargets := append(append([]*corev1.Pod{}, backends...), dnsBackends...)
	remoteTargets := remotePods(source, transitTargets)
	if len(remoteTargets) > 0 {
		traceContext := &model.NodeTransitContext{SourceNode: source.Spec.NodeName}
		for _, target := range remoteTargets {
			if !containsString(traceContext.DestinationNodes, target.Spec.NodeName) {
				traceContext.DestinationNodes = append(traceContext.DestinationNodes, target.Spec.NodeName)
			}
		}
		traceContext.Unavailable = planServiceTransit(
			command, ctx, client, sessionID, source, remoteTargets, plans,
		)
		serviceTrace.Context.NodeTransit = traceContext
	}
	serviceTrace.Context.Policies = relevantPolicies(command, ctx, client, source, backends)
	streams, err := startNodeAgents(ctx, client, options, sessionID, plans, index)
	if err != nil {
		return err
	}
	watchCtx, cancelWatch := captureWatchContext(ctx, streams)
	defer cancelWatch()
	streams = append(streams, startPolicyContextStream(
		command, watchCtx, client, sessionID, serviceTrace.Context, source, backends,
	))
	streams = append(streams, startServiceTopologyStream(
		command, watchCtx, client, source, *serviceTrace.Context.Service, serviceTrace.Context.Backends,
	))
	deliveryCtx, cleanup := traceStreamContext(ctx, streams)
	defer func() {
		traceErr = errors.Join(traceErr, cleanup())
	}()
	observations, errors := mergeStreams(deliveryCtx, streams...)
	observations = filterTraceObservations(deliveryCtx, serviceTrace.Context, observations)
	observations = prependTraceContext(deliveryCtx, sessionID, serviceTrace.Context, observations)
	title := source.Namespace + "/" + source.Name + " → " + serviceTrace.Context.Service.DisplayName()
	return consume(command, ctx, title, observations, errors, options.noTUI)
}

func endpointsForPods(endpoints []model.Endpoint, pods []*corev1.Pod) []model.Endpoint {
	selected := make(map[string]bool, len(pods))
	for _, pod := range pods {
		selected[pod.Namespace+"/"+pod.Name] = true
	}
	result := make([]model.Endpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Kind == model.EndpointPod && selected[endpoint.Namespace+"/"+endpoint.Name] {
			result = append(result, endpoint)
		}
	}
	return result
}

func startServiceTopologyStream(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	source *corev1.Pod,
	service model.Endpoint,
	initial []model.Endpoint,
) *kube.AgentStream {
	observations := make(chan model.Observation)
	close(observations)
	errors := make(chan error, 1)
	go func() {
		defer close(errors)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		initialSignature := endpointSignature(initial)
		lastWarning := ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current, err := client.ResolveServiceTrace(
					ctx, source, service.Namespace+"/"+service.Name,
				)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					if err.Error() != lastWarning {
						fmt.Fprintf(command.ErrOrStderr(), "warning: Service topology refresh failed: %v\n", err)
						lastWarning = err.Error()
					}
					continue
				}
				lastWarning = ""
				if endpointSignature(current.Context.Backends) == initialSignature {
					continue
				}
				errors <- fmt.Errorf(
					"Service backend topology changed while tracing; restart the trace to instrument the current ready backends",
				)
				return
			}
		}
	}()
	return &kube.AgentStream{
		Observations: observations,
		Errors:       errors,
		AttachmentID: "service-topology",
		Side:         "context",
	}
}

func endpointSignature(endpoints []model.Endpoint) string {
	values := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		values = append(values, fmt.Sprintf(
			"%s/%s/%s/%d/%s", endpoint.Namespace, endpoint.Name,
			endpoint.Address, endpoint.Port, endpoint.Node,
		))
	}
	sort.Strings(values)
	return strings.Join(values, "\n")
}

func startPolicyContextStream(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	sessionID string,
	traceContext model.TraceContext,
	source *corev1.Pod,
	destinations []*corev1.Pod,
) *kube.AgentStream {
	return policyContextStream(
		command, ctx, client, sessionID, traceContext, source, destinations, time.Second,
	)
}

func policyContextStream(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	sessionID string,
	traceContext model.TraceContext,
	source *corev1.Pod,
	destinations []*corev1.Pod,
	refreshInterval time.Duration,
) *kube.AgentStream {
	observations := make(chan model.Observation, 1)
	errors := make(chan error)
	close(errors)
	go func() {
		defer close(observations)
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		current := traceContext.Policies
		lastWarning := ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				policies, warnings := client.RelevantNetworkPolicies(ctx, source, destinations)
				if ctx.Err() != nil {
					return
				}
				for _, warning := range warnings {
					message := warning.Error()
					if message != lastWarning {
						fmt.Fprintf(command.ErrOrStderr(), "warning: NetworkPolicy context refresh failed: %v\n", warning)
						lastWarning = message
					}
				}
				if len(warnings) > 0 || reflect.DeepEqual(current, policies) {
					continue
				}
				lastWarning = ""
				current = policies
				updated := traceContext
				updated.Policies = policies
				select {
				case observations <- model.Observation{
					SchemaVersion: model.SchemaVersion,
					Kind:          model.KindTraceContext,
					SessionID:     sessionID,
					WallTime:      time.Now(),
					Confidence:    model.ConfidenceExact,
					Trace:         &updated,
					Evidence:      []string{"refreshed Kubernetes NetworkPolicy metadata"},
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return &kube.AgentStream{
		Observations: observations,
		Errors:       errors,
		AttachmentID: "policy-context",
		Side:         "context",
	}
}

func relevantPolicies(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	source *corev1.Pod,
	destinations []*corev1.Pod,
) []model.PolicyContext {
	policies, warnings := client.RelevantNetworkPolicies(ctx, source, destinations)
	for _, warning := range warnings {
		fmt.Fprintf(command.ErrOrStderr(), "warning: NetworkPolicy context unavailable: %v\n", warning)
	}
	return policies
}

type nodeAgentPlans map[string][]kube.AgentTarget

func (p nodeAgentPlans) addPod(
	pod *corev1.Pod,
	attachmentID, side string,
	captureConnect bool,
	flowAddresses []string,
) {
	p[pod.Spec.NodeName] = append(p[pod.Spec.NodeName], kube.AgentTarget{
		PodUID: string(pod.UID), AttachmentID: attachmentID, Side: side,
		CaptureConnect: captureConnect, FlowAddresses: append([]string(nil), flowAddresses...),
	})
}

func traceFlowAddresses(context model.TraceContext) []string {
	endpoints := []model.Endpoint{context.Source}
	endpoints = append(endpoints, context.Frontends...)
	endpoints = append(endpoints, context.Backends...)
	endpoints = append(endpoints, context.DNSFrontends...)
	endpoints = append(endpoints, context.DNSBackends...)
	return endpointAddresses(endpoints...)
}

func endpointAddresses(endpoints ...model.Endpoint) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if !endpoint.Address.IsValid() {
			continue
		}
		value := endpoint.Address.String()
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (p nodeAgentPlans) addTransit(
	node, routeTo, attachmentID, side string,
	flowAddresses []string,
) {
	p[node] = append(p[node], kube.AgentTarget{
		AttachmentID: attachmentID, Side: side,
		RouteTo: routeTo, FlowAddresses: append([]string(nil), flowAddresses...),
	})
}

func startNodeAgents(
	ctx context.Context,
	client *kube.Client,
	options *traceOptions,
	sessionID string,
	plans nodeAgentPlans,
	index *enrich.Index,
) ([]*kube.AgentStream, error) {
	nodes := make([]string, 0, len(plans))
	for node := range plans {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	streams := make([]*kube.AgentStream, 0, len(nodes))
	for _, node := range nodes {
		stream, err := client.StartAgent(ctx, kube.AgentOptions{
			Namespace:       options.agentNamespace,
			Image:           options.agentImage,
			ImagePullSecret: options.agentImagePullSecret,
			Node:            node,
			SessionID:       sessionID,
			Targets:         plans[node],
		}, index)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("start node agent %s: %w", node, err),
				closeAgentStreams(streams),
			)
		}
		streams = append(streams, stream)
	}
	return streams, nil
}

func closeAgentStreams(streams []*kube.AgentStream) error {
	var errs []error
	for index := len(streams) - 1; index >= 0; index-- {
		if err := streams[index].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func planTransitPair(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	sessionID string,
	source, destination *corev1.Pod,
	plans nodeAgentPlans,
) []string {
	sourceAddress := podTraceEndpoint(source).Address
	destinationAddress := podTraceEndpoint(destination).Address
	if !sourceAddress.IsValid() || !destinationAddress.IsValid() {
		fmt.Fprintln(command.ErrOrStderr(), "warning: node transit observation unavailable: selected Pods have no usable IP pair")
		return []string{"source and destination node transit: selected Pods have no usable IP pair"}
	}
	return planTransitForNodes(command, ctx, client, sessionID, source,
		map[string][]string{destination.Spec.NodeName: []string{destinationAddress.String()}}, plans)
}

func planServiceTransit(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	sessionID string,
	source *corev1.Pod,
	backends []*corev1.Pod,
	plans nodeAgentPlans,
) []string {
	sourceAddress := podTraceEndpoint(source).Address
	if !sourceAddress.IsValid() {
		fmt.Fprintln(command.ErrOrStderr(), "warning: node transit observation unavailable: source Pod has no usable IP")
		return []string{"source node transit: source Pod has no usable IP"}
	}
	byNode := make(map[string][]string)
	for _, backend := range backends {
		address := podTraceEndpoint(backend).Address
		if !address.IsValid() {
			continue
		}
		byNode[backend.Spec.NodeName] = append(byNode[backend.Spec.NodeName], address.String())
	}
	return planTransitForNodes(command, ctx, client, sessionID, source, byNode, plans)
}

func planTransitForNodes(
	command *cobra.Command,
	ctx context.Context,
	client *kube.Client,
	sessionID string,
	source *corev1.Pod,
	destinations map[string][]string,
	plans nodeAgentPlans,
) []string {
	var unavailable []string
	sourceAddress := podTraceEndpoint(source).Address
	sourceNodeAddress, sourceNodeAddressErr := client.NodeInternalAddress(ctx, source.Spec.NodeName)
	for node, destinationAddresses := range destinations {
		remoteAddress, err := client.NodeInternalAddress(ctx, node)
		if err != nil {
			fmt.Fprintf(command.ErrOrStderr(), "warning: source node transit observation unavailable for %s: %v\n", node, err)
			unavailable = append(unavailable, source.Spec.NodeName+"/underlay: "+err.Error())
			continue
		}
		plans.addTransit(
			source.Spec.NodeName, remoteAddress.String(), "transit-source-"+node, "transit-source",
			append([]string{sourceAddress.String()}, destinationAddresses...),
		)

		if sourceNodeAddressErr != nil {
			fmt.Fprintf(command.ErrOrStderr(), "warning: destination node transit observation unavailable for %s: %v\n", node, sourceNodeAddressErr)
			unavailable = append(unavailable, node+"/underlay: "+sourceNodeAddressErr.Error())
			continue
		}
		flowAddresses := append([]string{sourceAddress.String()}, destinationAddresses...)
		plans.addTransit(
			node, sourceNodeAddress.String(), "transit-destination-"+node, "transit-destination",
			flowAddresses,
		)
	}
	return unavailable
}

func remotePods(source *corev1.Pod, pods []*corev1.Pod) []*corev1.Pod {
	result := make([]*corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		if pod.Spec.NodeName != source.Spec.NodeName {
			result = append(result, pod)
		}
	}
	return result
}

func uniquePods(pods []*corev1.Pod) []*corev1.Pod {
	result := make([]*corev1.Pod, 0, len(pods))
	seen := make(map[string]bool)
	for _, pod := range pods {
		key := string(pod.UID)
		if key == "" {
			key = pod.Namespace + "/" + pod.Name
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, pod)
	}
	return result
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func filterTraceObservations(
	ctx context.Context,
	traceContext model.TraceContext,
	input <-chan model.Observation,
) <-chan model.Observation {
	output := make(chan model.Observation, 1024)
	go func() {
		defer close(output)
		for observation := range input {
			if !traceview.Relevant(observation, traceContext) {
				continue
			}
			select {
			case output <- observation:
			case <-ctx.Done():
				return
			}
		}
	}()
	return output
}

func prependTraceContext(
	ctx context.Context,
	sessionID string,
	traceContext model.TraceContext,
	input <-chan model.Observation,
) <-chan model.Observation {
	output := make(chan model.Observation, 1024)
	go func() {
		defer close(output)
		initial := model.Observation{
			SchemaVersion: model.SchemaVersion,
			Kind:          model.KindTraceContext,
			SessionID:     sessionID,
			WallTime:      time.Now(),
			Confidence:    model.ConfidenceExact,
			Trace:         &traceContext,
			Evidence:      []string{"resolved trace target", "Kubernetes resource metadata"},
		}
		select {
		case output <- initial:
		case <-ctx.Done():
			return
		}
		for observation := range input {
			select {
			case output <- observation:
			case <-ctx.Done():
				return
			}
		}
	}()
	return output
}
