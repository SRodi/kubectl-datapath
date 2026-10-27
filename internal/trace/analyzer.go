package trace

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

type Stage struct {
	Name       string
	Endpoint   model.Endpoint
	Detail     string
	Confidence model.Confidence
	Time       time.Time
}

type EvidencePoint struct {
	State  string
	Detail string
}

type DatapathView struct {
	Source               model.Endpoint
	SourceNode           string
	Destination          model.Endpoint
	DestinationNode      string
	Focus                string
	FocusDetail          string
	AttemptSuperseded    bool
	Connect              *EvidencePoint
	ConnectKind          string
	ConnectLabel         string
	SourceBoundary       EvidencePoint
	SourceTransit        *EvidencePoint
	DestinationTransit   *EvidencePoint
	DestinationBoundary  EvidencePoint
	SourceInterface      model.Observation
	DestinationInterface model.Observation
	TransitLabel         string
	CrossNode            bool
	CaptureComplete      bool
	Diagnosis            string
	Policies             []model.PolicyContext
}

type Analyzer struct {
	context             *model.TraceContext
	pendingIntent       *model.Observation
	pendingBackend      map[attemptKey]model.Observation
	pendingResponse     map[attemptKey]model.Observation
	attempts            map[attemptKey]*attempt
	active              *attempt
	ready               map[string]model.Observation
	attachments         map[string]model.Observation
	finalStatuses       map[string]model.Observation
	lost                map[string]uint64
	transportLost       map[string]uint64
	packets             map[string]int
	transit             []model.Observation
	dnsIntent           *model.Observation
	dnsQueries          []model.Observation
	dnsResponses        []model.Observation
	dnsBackendQueries   []model.Observation
	dnsBackendResponses []model.Observation
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		attempts:        make(map[attemptKey]*attempt),
		pendingBackend:  make(map[attemptKey]model.Observation),
		pendingResponse: make(map[attemptKey]model.Observation),
		ready:           make(map[string]model.Observation),
		attachments:     make(map[string]model.Observation),
		finalStatuses:   make(map[string]model.Observation),
		lost:            make(map[string]uint64),
		transportLost:   make(map[string]uint64),
		packets:         make(map[string]int),
	}
}

type attemptKey struct {
	Protocol        uint8
	SourceAddr      netip.Addr
	SourcePort      uint16
	InitialSequence uint32
}

type attempt struct {
	key        attemptKey
	intent     *model.Observation
	sourceSYNs []model.Observation
	backendSYN *model.Observation
	response   *model.Observation
}

type clientKey struct {
	Protocol   uint8
	SourceAddr netip.Addr
	SourcePort uint16
}

type AttemptSummary struct {
	Protocol         uint8
	SourceAddr       netip.Addr
	Started          time.Time
	LastSeen         time.Time
	SourcePort       uint16
	InitialSequence  uint32
	SYNs             int
	BackendObserved  bool
	ResponseObserved bool
	Reset            bool
	Active           bool
	Status           string
}

func (a *Analyzer) Observe(observation model.Observation) {
	if observation.Lost > a.lost[observation.Side] {
		a.lost[observation.Side] = observation.Lost
	}
	if observation.TransportLost > a.transportLost[observation.Side] {
		a.transportLost[observation.Side] = observation.TransportLost
	}
	switch observation.Kind {
	case model.KindTraceContext:
		a.context = observation.Trace
	case model.KindStatus:
		if observation.AttachmentID != "" {
			a.ready[observation.Side] = observation
			a.attachments[observation.AttachmentID] = observation
			if observation.Final {
				a.finalStatuses[observation.AttachmentID] = observation
			}
		}
	case model.KindConnect:
		if observation.Side == "source" && observation.DstPort == 53 {
			copy := observation
			a.dnsIntent = &copy
		}
		if a.context != nil && observation.Side == "source" &&
			matchesAny(observation.DstAddr, observation.DstPort, a.context.Frontends) {
			copy := observation
			a.pendingIntent = &copy
		}
	case model.KindPacket:
		if a.context == nil {
			return
		}
		a.packets[observation.Side]++
		a.observeDNS(observation)
		if observation.Side == "source" && sourceToTarget(observation, *a.context) && initialSYN(observation) {
			a.observeSourceSYN(observation)
		}
		if observation.Side == "backend" && initialSYN(observation) &&
			matchesAny(observation.DstAddr, observation.DstPort, a.context.Backends) {
			a.observeBackendSYN(observation)
		}
		if responseFromBackend(observation, *a.context) {
			a.observeResponse(observation)
		}
	case model.KindTransit:
		if a.context != nil {
			a.transit = append(a.transit, observation)
		}
	}
}

type TransitActivity struct {
	Observations []model.Observation
	Attachments  []Health
	Conclusion   string
}

func (a *Analyzer) Transit() *TransitActivity {
	if a.context == nil || a.context.NodeTransit == nil {
		return nil
	}
	if focus := a.latestDNSFocus(); focus != nil {
		return a.transitActivity(func(observation model.Observation) bool {
			return a.transitMatchesDNS(observation, *focus)
		})
	}
	return a.transitActivity(a.transitMatchesCurrent)
}

func (a *Analyzer) transitActivity(matches func(model.Observation) bool) *TransitActivity {
	activity := &TransitActivity{}
	for _, observation := range a.transit {
		if matches(observation) {
			activity.Observations = append(activity.Observations, observation)
		}
	}
	sort.SliceStable(activity.Observations, func(i, j int) bool {
		left, right := activity.Observations[i], activity.Observations[j]
		if left.Node != right.Node {
			return left.Node < right.Node
		}
		return left.MonotonicNS < right.MonotonicNS
	})
	attachmentIDs := make([]string, 0)
	for id := range a.attachments {
		if len(id) >= len("transit-") && id[:len("transit-")] == "transit-" {
			attachmentIDs = append(attachmentIDs, id)
		}
	}
	sort.Strings(attachmentIDs)
	for _, id := range attachmentIDs {
		ready := a.attachments[id]
		observed := false
		for _, observation := range activity.Observations {
			if observation.AttachmentID == id {
				observed = true
				break
			}
		}
		name := ready.Node + "/underlay"
		health := a.healthWithLoss(name, observed, ready, "selected inner tuple", ready.Side)
		health.AttachmentID = id
		health.Node = ready.Node
		health.Side = ready.Side
		activity.Attachments = append(activity.Attachments, health)
	}
	for _, unavailable := range a.context.NodeTransit.Unavailable {
		activity.Attachments = append(activity.Attachments, Health{
			Name: "node/underlay", State: "UNAVAILABLE", Detail: unavailable,
		})
	}
	nodes := make(map[string]bool)
	encapsulations := make(map[model.Encapsulation]bool)
	for _, observation := range activity.Observations {
		nodes[observation.Node] = true
		encapsulations[observation.Encapsulation] = true
	}
	switch {
	case len(nodes) >= 2 && encapsulations[model.EncapsulationVXLAN]:
		activity.Conclusion = "VXLAN transit observed on both route-selected node interfaces; node clocks are not compared"
	case len(nodes) >= 2 && encapsulations[model.EncapsulationNative]:
		activity.Conclusion = "Native routed transit observed on both route-selected node interfaces; node clocks are not compared"
	case len(activity.Observations) > 0:
		activity.Conclusion = "Node transit observed on only part of the selected cross-node path"
	case len(a.context.NodeTransit.Unavailable) > 0:
		activity.Conclusion = "Node-transit observation is unavailable at one or more requested interfaces"
	default:
		activity.Conclusion = "No matching node-transit packet observed yet"
	}
	return activity
}

func (a *Analyzer) transitMatchesCurrent(observation model.Observation) bool {
	switch a.mode() {
	case model.TraceModePod:
		if a.context.Destination == nil {
			return false
		}
		return (observation.SrcAddr == a.context.Source.Address && observation.DstAddr == a.context.Destination.Address) ||
			(observation.SrcAddr == a.context.Destination.Address && observation.DstAddr == a.context.Source.Address)
	case model.TraceModeService:
		if a.active == nil {
			return false
		}
		return observation.Protocol == a.active.key.Protocol &&
			initialSYN(observation) &&
			observation.TCPSequence == a.active.key.InitialSequence &&
			((observation.SrcAddr == a.active.key.SourceAddr && observation.SrcPort == a.active.key.SourcePort &&
				matchesAddress(observation.DstAddr, a.context.Backends)) ||
				(observation.DstAddr == a.active.key.SourceAddr && observation.DstPort == a.active.key.SourcePort &&
					matchesAddress(observation.SrcAddr, a.context.Backends)))
	default:
		return false
	}
}

type dnsFocus struct {
	query       model.Observation
	destination model.Endpoint
}

func (a *Analyzer) latestDNSFocus() *dnsFocus {
	if a.context == nil || len(a.dnsQueries) == 0 {
		return nil
	}
	latest := a.dnsQueries[0]
	for _, observation := range a.dnsQueries[1:] {
		if observation.WallTime.After(latest.WallTime) {
			latest = observation
		}
	}
	key := clientKey{Protocol: latest.Protocol, SourceAddr: latest.SrcAddr, SourcePort: latest.SrcPort}
	for _, response := range filterDNSResponses(a.dnsResponses, key) {
		if response.WallTime.After(latest.WallTime) {
			return nil
		}
	}
	if a.dnsIntent == nil || a.dnsIntent.WallTime.After(latest.WallTime) ||
		latest.WallTime.Sub(a.dnsIntent.WallTime) > 10*time.Second {
		return nil
	}
	if a.active != nil {
		if a.active.intent == nil || a.active.intent.CgroupID == 0 || a.dnsIntent.CgroupID == 0 ||
			a.active.intent.CgroupID != a.dnsIntent.CgroupID {
			return nil
		}
	}
	if a.active != nil && !latest.WallTime.After(a.attemptLastSourceSeen(a.active)) {
		return nil
	}
	return &dnsFocus{query: latest, destination: endpointFor(latest, a.context)}
}

func (a *Analyzer) attemptLastSourceSeen(current *attempt) time.Time {
	if current == nil || len(current.sourceSYNs) == 0 {
		return time.Time{}
	}
	lastSeen := current.sourceSYNs[len(current.sourceSYNs)-1].WallTime
	if current.intent != nil && current.intent.WallTime.After(lastSeen) {
		lastSeen = current.intent.WallTime
	}
	return lastSeen
}

func (a *Analyzer) transitMatchesDNS(observation model.Observation, focus dnsFocus) bool {
	query := focus.query
	if observation.Protocol != query.Protocol {
		return false
	}
	forward := observation.SrcAddr == query.SrcAddr &&
		observation.SrcPort == query.SrcPort &&
		observation.DstPort == 53 &&
		(matchesAddress(observation.DstAddr, a.context.DNSBackends) ||
			matchesAddress(observation.DstAddr, a.context.DNSFrontends))
	reverse := observation.DstAddr == query.SrcAddr &&
		observation.DstPort == query.SrcPort &&
		observation.SrcPort == 53 &&
		(matchesAddress(observation.SrcAddr, a.context.DNSBackends) ||
			matchesAddress(observation.SrcAddr, a.context.DNSFrontends))
	return forward || reverse
}

func (a *Analyzer) observeDNS(observation model.Observation) {
	if observation.Protocol != 6 && observation.Protocol != 17 {
		return
	}
	sourceQuery := observation.DstPort == 53 &&
		sourceIdentityOrAddress(observation.SrcEndpoint, observation.SrcAddr, a.context.Source)
	sourceResponse := observation.SrcPort == 53 &&
		sourceIdentityOrAddress(observation.DstEndpoint, observation.DstAddr, a.context.Source)
	switch observation.Side {
	case "source":
		if sourceQuery {
			a.dnsQueries = append(a.dnsQueries, observation)
		}
		if sourceResponse {
			a.dnsResponses = append(a.dnsResponses, observation)
		}
	case "dns":
		if sourceQuery && matchesAny(observation.DstAddr, observation.DstPort, a.context.DNSBackends) {
			a.dnsBackendQueries = append(a.dnsBackendQueries, observation)
		}
		if sourceResponse && matchesAddress(observation.SrcAddr, a.context.DNSBackends) {
			a.dnsBackendResponses = append(a.dnsBackendResponses, observation)
		}
	}
}

func (a *Analyzer) observeSourceSYN(observation model.Observation) {
	key := attemptKey{
		Protocol: observation.Protocol, SourceAddr: observation.SrcAddr,
		SourcePort: observation.SrcPort, InitialSequence: observation.TCPSequence,
	}
	current := a.attempts[key]
	if current == nil {
		current = &attempt{key: key}
		if a.pendingIntent != nil {
			elapsed := observation.WallTime.Sub(a.pendingIntent.WallTime)
			if elapsed >= 0 && elapsed <= 10*time.Second {
				copy := *a.pendingIntent
				current.intent = &copy
				a.pendingIntent = nil
			}
		}
		a.attempts[key] = current
		if backend, ok := a.pendingBackend[key]; ok {
			copy := backend
			current.backendSYN = &copy
			delete(a.pendingBackend, key)
		}
		if response, ok := a.pendingResponse[key]; ok {
			copy := response
			current.response = &copy
			delete(a.pendingResponse, key)
		}
	}
	current.sourceSYNs = append(current.sourceSYNs, observation)
	if a.active == nil || current.sourceSYNs[0].WallTime.After(a.active.sourceSYNs[0].WallTime) {
		a.active = current
	}
}

func (a *Analyzer) observeBackendSYN(observation model.Observation) {
	key := attemptKey{
		Protocol: observation.Protocol, SourceAddr: observation.SrcAddr,
		SourcePort: observation.SrcPort, InitialSequence: observation.TCPSequence,
	}
	if current := a.attempts[key]; current != nil {
		copy := observation
		current.backendSYN = &copy
		return
	}
	a.pendingBackend[key] = observation
}

func (a *Analyzer) observeResponse(observation model.Observation) {
	key, ok := responseAttemptKey(observation)
	if !ok {
		return
	}
	if matched := a.attempts[key]; matched != nil {
		copy := observation
		matched.response = &copy
	} else {
		a.pendingResponse[key] = observation
	}
}

func responseAttemptKey(observation model.Observation) (attemptKey, bool) {
	if observation.Protocol != 6 || observation.TCPFlags&0x10 == 0 || observation.TCPAck == 0 {
		return attemptKey{}, false
	}
	// A SYN consumes one sequence number, so ACK-1 reconstructs the initiating SYN key.
	return attemptKey{
		Protocol: observation.Protocol, SourceAddr: observation.DstAddr,
		SourcePort: observation.DstPort, InitialSequence: observation.TCPAck - 1,
	}, true
}

func (a *Analyzer) Attempts() []AttemptSummary {
	summaries := make([]AttemptSummary, 0, len(a.attempts))
	for _, current := range a.attempts {
		if len(current.sourceSYNs) == 0 {
			continue
		}
		started := current.sourceSYNs[0].WallTime
		lastSeen := current.sourceSYNs[len(current.sourceSYNs)-1].WallTime
		if current.backendSYN != nil && current.backendSYN.WallTime.After(lastSeen) {
			lastSeen = current.backendSYN.WallTime
		}
		if current.response != nil && current.response.WallTime.After(lastSeen) {
			lastSeen = current.response.WallTime
		}
		summary := AttemptSummary{
			Protocol:         current.key.Protocol,
			SourceAddr:       current.key.SourceAddr,
			Started:          started,
			LastSeen:         lastSeen,
			SourcePort:       current.key.SourcePort,
			InitialSequence:  current.key.InitialSequence,
			SYNs:             len(current.sourceSYNs),
			BackendObserved:  current.backendSYN != nil,
			ResponseObserved: current.response != nil,
			Reset:            current.response != nil && current.response.IsTCPReset(),
			Active:           current == a.active,
		}
		switch {
		case summary.BackendObserved && summary.Reset:
			summary.Status = "backend SYN and reset observed (connection refused)"
		case summary.BackendObserved && summary.ResponseObserved:
			summary.Status = "backend SYN and response observed"
		case summary.Reset:
			summary.Status = "reset observed; no backend SYN observed"
		case summary.BackendObserved:
			summary.Status = "backend SYN observed; no response observed"
		case summary.SYNs > 1:
			summary.Status = fmt.Sprintf("%d SYNs; no backend SYN or response observed", summary.SYNs)
		default:
			summary.Status = "source SYN observed; no backend SYN or response observed"
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Started.After(summaries[j].Started)
	})
	return summaries
}

func (a *Analyzer) IsServiceTrace() bool {
	return a.mode() == model.TraceModeService
}

func (a *Analyzer) Datapath() *DatapathView {
	if a.context == nil {
		return nil
	}
	dnsFocus := a.latestDNSFocus()
	view := &DatapathView{
		Source:         a.context.Source,
		SourceNode:     a.context.Source.Node,
		Destination:    a.diagramDestination(),
		Focus:          "backend TCP attempt",
		ConnectKind:    "connect intent",
		SourceBoundary: EvidencePoint{State: "NOT READY", Detail: "source attachment has not reported readiness"},
		TransitLabel:   "node underlay",
	}
	if view.SourceNode == "" && a.context.NodeTransit != nil {
		view.SourceNode = a.context.NodeTransit.SourceNode
	}
	healthByName := make(map[string]Health)
	for _, current := range a.Health() {
		healthByName[current.Name] = current
	}
	if dnsFocus != nil {
		view.Focus = "DNS prerequisite"
		view.AttemptSuperseded = a.active != nil
		if view.AttemptSuperseded {
			view.FocusDetail = fmt.Sprintf(
				"newer unresolved DNS query from the same source cgroup at %s supersedes the last backend TCP attempt; DNS qname is not captured",
				dnsFocus.query.WallTime.Format("15:04:05.000000"),
			)
		} else {
			view.FocusDetail = fmt.Sprintf(
				"unresolved DNS query at %s; backend TCP connect has not started; DNS qname is not captured",
				dnsFocus.query.WallTime.Format("15:04:05.000000"),
			)
		}
		view.Destination = dnsFocus.destination
		view.ConnectKind = "DNS intent"
		intent := health("source/application", a.dnsIntent != nil, a.ready["source"], "DNS connect intent")
		connect := evidencePoint(intent)
		view.Connect = &connect
		view.ConnectLabel = view.Destination.DisplayName()
		if a.dnsIntent != nil {
			view.ConnectLabel = endpointFor(*a.dnsIntent, a.context).DisplayName()
		}
		view.SourceBoundary = evidencePoint(
			a.healthWithLoss("source/boundary", true, a.ready["source"], "matching DNS query", "source"),
		)
		key := clientKey{
			Protocol:   dnsFocus.query.Protocol,
			SourceAddr: dnsFocus.query.SrcAddr,
			SourcePort: dnsFocus.query.SrcPort,
		}
		backendObserved := len(filterDNSQueries(a.dnsBackendQueries, key)) > 0
		view.DestinationBoundary = evidencePoint(
			a.healthWithLoss("dns/boundary", backendObserved, a.ready["dns"], "matching DNS query", "dns"),
		)
	} else if a.mode() == model.TraceModeService {
		connect := evidencePoint(healthByName["source/application"])
		view.Connect = &connect
		if a.active != nil && a.active.intent != nil {
			view.ConnectLabel = endpointFor(*a.active.intent, a.context).DisplayName()
		} else if a.context.Service != nil {
			view.ConnectLabel = a.context.Service.DisplayName()
		}
		view.SourceBoundary = evidencePoint(healthByName["source/boundary"])
		view.DestinationBoundary = evidencePoint(healthByName["backend/boundary"])
		if a.backendUnavailable(
			view.DestinationBoundary.State == "OBSERVED",
			view.Destination,
		) {
			view.DestinationBoundary = EvidencePoint{
				State:  "UNAVAILABLE",
				Detail: "selected backend was not instrumented because it exceeds --max-backends",
			}
		}
	} else {
		view.Focus = "selected pod traffic"
		view.SourceBoundary = evidencePoint(healthByName["source/boundary"])
		view.DestinationBoundary = evidencePoint(healthByName["destination/boundary"])
	}

	view.DestinationNode = view.Destination.Node
	if view.DestinationNode == "" && dnsFocus == nil && a.context.NodeTransit != nil {
		view.DestinationNode = strings.Join(a.context.NodeTransit.DestinationNodes, ",")
	}
	view.CrossNode = view.SourceNode != "" && view.DestinationNode != "" &&
		view.SourceNode != view.DestinationNode
	sides := []string{"source", "backend"}
	if dnsFocus != nil {
		sides = []string{"source", "dns"}
	} else if a.mode() == model.TraceModePod {
		sides = []string{"source", "destination"}
	}
	view.SourceInterface = a.boundaryInterface(sides[0])
	view.DestinationInterface = a.boundaryInterface(sides[1])
	if dnsFocus == nil && a.mode() == model.TraceModeService &&
		a.active != nil && a.active.backendSYN != nil {
		view.DestinationInterface = *a.active.backendSYN
	}
	if view.CrossNode {
		sides = append(sides, "transit-source", "transit-destination")
	}
	view.CaptureComplete = a.captureCompleteForSides(sides...)
	if view.CrossNode && a.context.NodeTransit != nil {
		transit := a.Transit()
		sourceTransit := transitPoint(transit, view.SourceNode, "transit-source", view.DestinationNode)
		destinationTransit := transitPoint(transit, view.DestinationNode, "transit-destination", view.DestinationNode)
		view.SourceTransit = &sourceTransit
		view.DestinationTransit = &destinationTransit
		if transit != nil {
			for _, observation := range transit.Observations {
				switch observation.Encapsulation {
				case model.EncapsulationVXLAN:
					view.TransitLabel = fmt.Sprintf("VXLAN vni=%d", observation.TunnelID)
				case model.EncapsulationNative:
					if view.TransitLabel == "node underlay" {
						view.TransitLabel = "native routing"
					}
				}
			}
		}
	}
	view.Policies = a.diagramPolicies(view.Destination)
	view.Diagnosis = diagnoseDatapath(*view, a.mode(), dnsFocus != nil)
	if view.CaptureComplete && !strings.Contains(view.Diagnosis, "incomplete") {
		switch {
		case view.DestinationBoundary.State == "OBSERVED":
			view.Diagnosis += " Capture complete through final watermarks."
		case view.SourceBoundary.State == "OBSERVED":
			view.Diagnosis = "Capture complete through final watermarks. " +
				view.Diagnosis + " This is an evidence gap, not a drop verdict."
		default:
			view.Diagnosis = "Capture complete through final watermarks; no matching evidence was observed at the selected datapath boundaries."
		}
	}
	return view
}

func (a *Analyzer) backendUnavailable(observed bool, destination model.Endpoint) bool {
	// Direct packet evidence proves coverage even if the topology snapshot is stale or incomplete.
	return !observed && !a.backendInstrumented(destination)
}

func (a *Analyzer) backendInstrumented(destination model.Endpoint) bool {
	if a.context == nil || a.mode() != model.TraceModeService ||
		!a.context.BackendCoverageKnown || !destination.Address.IsValid() {
		return true
	}
	return matchesAddress(destination.Address, a.context.InstrumentedBackends)
}

func (a *Analyzer) diagramDestination() model.Endpoint {
	if a.mode() == model.TraceModePod && a.context.Destination != nil {
		return *a.context.Destination
	}
	if a.active != nil {
		if a.active.backendSYN != nil {
			return endpointFor(*a.active.backendSYN, a.context)
		}
		if len(a.active.sourceSYNs) > 0 {
			address := a.active.sourceSYNs[0].DstAddr
			for _, backend := range a.context.Backends {
				if backend.Address == address {
					return backend
				}
			}
		}
		for _, observation := range a.transit {
			if !a.transitMatchesCurrent(observation) {
				continue
			}
			for _, backend := range a.context.Backends {
				if backend.Address == observation.SrcAddr || backend.Address == observation.DstAddr {
					return backend
				}
			}
		}
	}
	if len(a.context.Backends) == 1 {
		return a.context.Backends[0]
	}
	return model.Endpoint{Kind: model.EndpointPod, Name: "ready Service backend"}
}

// Do not label a selected boundary using an arbitrary Service backend's link.
func (a *Analyzer) boundaryInterface(side string) model.Observation {
	var result model.Observation
	for _, observation := range a.attachments {
		if observation.Side != side {
			continue
		}
		if result.AttachmentID != "" {
			return model.Observation{}
		}
		result = observation
	}
	return result
}

func (a *Analyzer) Attachments() []model.Observation {
	result := make([]model.Observation, 0, len(a.attachments))
	for _, observation := range a.attachments {
		result = append(result, observation)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].AttachmentID < result[j].AttachmentID
	})
	return result
}

func evidencePoint(health Health) EvidencePoint {
	if health.State == "" {
		return EvidencePoint{State: "NOT READY", Detail: "capture point is not ready"}
	}
	return EvidencePoint{State: health.State, Detail: health.Detail}
}

func transitPoint(activity *TransitActivity, node, side, destinationNode string) EvidencePoint {
	if activity == nil {
		return EvidencePoint{State: "NOT READY", Detail: "underlay capture was not requested"}
	}

	for _, health := range activity.Attachments {
		if health.Node != node || health.Side != side {
			continue
		}
		if side == "transit-source" && destinationNode != "" &&
			!strings.HasSuffix(health.AttachmentID, "-"+destinationNode) {
			continue
		}
		if health.Name == node+"/underlay" {
			return evidencePoint(health)
		}
	}
	for _, health := range activity.Attachments {
		if health.State == "UNAVAILABLE" && (node == "" || strings.Contains(health.Detail, node+"/underlay")) {
			return evidencePoint(health)
		}
	}
	return EvidencePoint{State: "NOT READY", Detail: "underlay attachment has not reported readiness"}
}

func (a *Analyzer) diagramPolicies(destination model.Endpoint) []model.PolicyContext {
	var policies []model.PolicyContext
	unresolvedBackend := destination.Name == "ready Service backend"
	for _, policy := range a.context.Policies {
		if policy.Scope == "source egress" || destination.Name == "" || unresolvedBackend ||
			containsString(policy.Pods, destination.Name) {
			policies = append(policies, policy)
		}
	}
	return policies
}

func diagnoseDatapath(view DatapathView, mode model.TraceMode, dnsFocus bool) string {
	points := []EvidencePoint{view.SourceBoundary, view.DestinationBoundary}
	if view.Connect != nil {
		points = append(points, *view.Connect)
	}
	if view.SourceTransit != nil {
		points = append(points, *view.SourceTransit)
	}
	if view.DestinationTransit != nil {
		points = append(points, *view.DestinationTransit)
	}
	for _, point := range points {
		if point.State == "INCOMPLETE" {
			return "Trace incomplete: event loss prevents localizing the evidence gap."
		}
	}
	if view.DestinationBoundary.State == "UNAVAILABLE" {
		return "Trace incomplete: the selected backend exceeds --max-backends and was not instrumented."
	}
	evidence := "matching traffic"
	if dnsFocus {
		evidence = "matching DNS query"
	} else if mode == model.TraceModeService {
		evidence = "matching SYN"
	}
	if view.DestinationBoundary.State == "OBSERVED" {
		return fmt.Sprintf("%s observed through the destination Pod boundary.", capitalize(evidence))
	}
	if view.CrossNode && view.SourceBoundary.State == "OBSERVED" &&
		view.SourceTransit != nil && view.SourceTransit.State == "NO EVIDENCE" {
		return fmt.Sprintf(
			"Evidence gap: %s crossed the source Pod boundary, but not the source-node underlay; gap is inside the source node between the pod-facing interface and underlay egress.",
			evidence,
		)
	}
	if view.CrossNode && pointObserved(view.DestinationTransit) &&
		view.DestinationBoundary.State == "NO EVIDENCE" {
		return fmt.Sprintf(
			"Evidence gap: %s reached %s underlay, but not the destination Pod boundary; gap is inside the destination node between underlay ingress and the pod-facing interface.",
			evidence, view.DestinationNode,
		)
	}
	if view.CrossNode && pointObserved(view.SourceTransit) &&
		!pointObserved(view.DestinationTransit) {
		return fmt.Sprintf(
			"Evidence gap: %s left the source-node underlay, but was not observed at the destination-node underlay.",
			evidence,
		)
	}
	if view.SourceBoundary.State == "OBSERVED" && view.DestinationBoundary.State == "NO EVIDENCE" {
		return fmt.Sprintf(
			"Evidence gap: %s crossed the source Pod boundary, but not the destination Pod boundary.",
			evidence,
		)
	}
	if view.CaptureComplete {
		if view.SourceBoundary.State == "OBSERVED" {
			return fmt.Sprintf(
				"Capture complete through final watermarks: %s was observed at the source boundary, but no matching evidence reached the destination boundary (not a drop verdict).",
				evidence,
			)
		}
		return "Capture complete through final watermarks; no matching evidence was observed at the selected datapath boundaries."
	}
	return "Waiting for enough matching evidence to localize the path."
}

func pointObserved(point *EvidencePoint) bool {
	return point != nil && point.State == "OBSERVED"
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func capitalize(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func (a *Analyzer) Stages() []Stage {
	if a.context == nil {
		return nil
	}
	switch a.mode() {
	case model.TraceModePod:
		stages := []Stage{{
			Name: "Source Pod", Endpoint: a.context.Source,
			Detail: "First selected Pod boundary", Confidence: model.ConfidenceExact,
		}}
		if a.context.Destination != nil {
			stages = append(stages, Stage{
				Name: "Destination Pod", Endpoint: *a.context.Destination,
				Detail: "Second selected Pod boundary", Confidence: model.ConfidenceExact,
			})
		}
		return stages
	}
	if a.context.Service == nil {
		return nil
	}
	stages := []Stage{{
		Name: "Selected target", Endpoint: *a.context.Service,
		Detail: "Service selected by the trace command", Confidence: model.ConfidenceExact,
	}}
	if a.active != nil && a.active.intent != nil {
		stages = append(stages, Stage{
			Name: "Application connect", Endpoint: endpointFor(*a.active.intent, a.context),
			Detail:     "Destination read at connect() entry in the source Pod cgroup",
			Confidence: model.ConfidenceExact, Time: a.active.intent.WallTime,
		})
	}
	if a.active != nil && len(a.active.sourceSYNs) > 0 {
		source := a.active.sourceSYNs[0]
		detail := "Initial SYN observed on the source pod-facing interface"
		if len(a.active.sourceSYNs) > 1 {
			delay := a.active.sourceSYNs[len(a.active.sourceSYNs)-1].WallTime.Sub(source.WallTime)
			detail = fmt.Sprintf("%d SYN observations; latest retransmission after %s",
				len(a.active.sourceSYNs), delay.Round(time.Microsecond))
		}
		stages = append(stages, Stage{
			Name: "Source Pod boundary", Endpoint: endpointFor(source, a.context),
			Detail: detail, Confidence: model.ConfidenceExact, Time: source.WallTime,
		})
	}
	if a.active != nil && a.active.backendSYN != nil {
		stages = append(stages, Stage{
			Name: "Backend boundary", Endpoint: endpointFor(*a.active.backendSYN, a.context),
			Detail:     "Matching SYN observed entering a ready Service backend",
			Confidence: model.ConfidenceExact, Time: a.active.backendSYN.WallTime,
		})
	}
	return stages
}

func (a *Analyzer) Conclusion() string {
	if a.context == nil {
		return ""
	}
	switch a.mode() {
	case model.TraceModePod:
		sourceObserved := a.packets["source"] > 0
		destinationObserved := a.packets["destination"] > 0
		switch {
		case sourceObserved && destinationObserved:
			return "Correlated traffic observed at both selected Pod boundaries"
		case sourceObserved:
			if a.sideCaptureComplete("source") && a.sideCaptureComplete("destination") {
				return "Capture complete; source traffic was observed without matching destination evidence (not a drop verdict)"
			}
			return "Traffic observed at the source boundary; waiting for matching destination-boundary evidence"
		case destinationObserved:
			if a.sideCaptureComplete("source") && a.sideCaptureComplete("destination") {
				return "Capture complete; destination traffic was observed without matching source evidence (not a drop verdict)"
			}
			return "Traffic observed at the destination boundary; waiting for matching source-boundary evidence"
		default:
			if a.sideCaptureComplete("source") && a.sideCaptureComplete("destination") {
				return "Capture complete; no matching traffic was observed at the selected Pod boundaries"
			}
			return "Waiting for traffic between the selected Pod boundaries"
		}
	}
	if a.active == nil || len(a.active.sourceSYNs) == 0 {
		return "Waiting for a Service connect and matching source-boundary packet"
	}
	source := a.active.sourceSYNs[0]
	if a.active.backendSYN == nil {
		if a.lost["source"] > 0 || a.lost["backend"] > 0 ||
			a.transportLost["source"] > 0 || a.transportLost["backend"] > 0 {
			return "Trace incomplete: event loss prevents interpreting the missing backend SYN"
		}
		if a.sideCaptureComplete("source") && a.sideCaptureComplete("backend") {
			return "Capture complete through final watermarks; no matching backend SYN was observed (not a drop verdict)"
		}
		if len(a.active.sourceSYNs) > 1 {
			return fmt.Sprintf(
				"Correlated gap: %d source SYNs, no matching backend SYN; consistent with a drop between observation points",
				len(a.active.sourceSYNs),
			)
		}
		return "Source SYN observed; waiting for a matching backend SYN"
	}
	if a.active.intent == nil {
		return "Matching source and backend SYN observed; application intent was not captured"
	}
	intentFrontend := matchesAny(a.active.intent.DstAddr, a.active.intent.DstPort, a.context.Frontends)
	packetFrontend := matchesAny(source.DstAddr, source.DstPort, a.context.Frontends)
	packetBackend := matchesAddress(source.DstAddr, a.context.Backends)
	switch {
	case intentFrontend && packetFrontend:
		return "Correlated evidence: Service frontend at source boundary and backend address at backend boundary; translation occurred between them"
	case intentFrontend && packetBackend:
		return "Correlated evidence: destination changed to a Service backend before the source Pod boundary"
	default:
		return "Observed tuples do not yet prove a Service translation location"
	}

}

func (a *Analyzer) sideCaptureComplete(side string) bool {
	found := false
	for attachmentID, status := range a.attachments {
		if status.Side != side {
			continue
		}
		found = true
		final, ok := a.finalStatuses[attachmentID]
		if !ok || !final.Complete {
			return false
		}
	}
	return found
}

func (a *Analyzer) captureCompleteForSides(sides ...string) bool {
	for _, side := range sides {
		if !a.sideCaptureComplete(side) {
			return false
		}
	}
	return true
}

type Health struct {
	Name         string
	State        string
	Detail       string
	AttachmentID string
	Node         string
	Side         string
}

type DNSActivity struct {
	Intent              *model.Endpoint
	Observed            *model.Endpoint
	Responders          []model.Endpoint
	Queries             int
	Responses           int
	BackendQueries      int
	BackendResponses    int
	Observations        []model.Observation
	BackendObservations []model.Observation
	Conclusion          string
}

func (a *Analyzer) DNS() *DNSActivity {
	if a.dnsIntent == nil && len(a.dnsQueries) == 0 && len(a.dnsResponses) == 0 &&
		len(a.dnsBackendQueries) == 0 && len(a.dnsBackendResponses) == 0 {
		return nil
	}
	queries, responses := a.dnsQueries, a.dnsResponses
	backendQueries, backendResponses := a.dnsBackendQueries, a.dnsBackendResponses
	if len(a.dnsQueries) > 0 {
		latest := a.dnsQueries[0]
		for _, observation := range a.dnsQueries[1:] {
			if observation.WallTime.After(latest.WallTime) {
				latest = observation
			}
		}
		key := clientKey{Protocol: latest.Protocol, SourceAddr: latest.SrcAddr, SourcePort: latest.SrcPort}
		queries = filterDNSQueries(a.dnsQueries, key)
		responses = filterDNSResponses(a.dnsResponses, key)
		backendQueries = filterDNSQueries(a.dnsBackendQueries, key)
		backendResponses = filterDNSResponses(a.dnsBackendResponses, key)
	}
	activity := &DNSActivity{
		Queries:             len(queries),
		Responses:           len(responses),
		Observations:        append(append([]model.Observation{}, queries...), responses...),
		BackendQueries:      len(backendQueries),
		BackendResponses:    len(backendResponses),
		BackendObservations: append(append([]model.Observation{}, backendQueries...), backendResponses...),
	}
	if a.dnsIntent != nil {
		endpoint := destinationEndpoint(*a.dnsIntent)
		activity.Intent = &endpoint
	}
	if len(a.dnsQueries) > 0 {
		endpoint := destinationEndpoint(a.dnsQueries[0])
		activity.Observed = &endpoint
	}
	responders := make(map[string]model.Endpoint)
	for _, observation := range append(append([]model.Observation{}, backendQueries...), backendResponses...) {
		endpoint := observation.DstEndpoint
		if observation.SrcPort == 53 {
			endpoint = observation.SrcEndpoint
		}
		if endpoint != nil {
			responders[endpoint.Namespace+"/"+endpoint.Name+"/"+endpoint.Address.String()] = *endpoint
		}
	}
	for _, responder := range responders {
		activity.Responders = append(activity.Responders, responder)
	}
	sort.Slice(activity.Responders, func(i, j int) bool {
		return activity.Responders[i].DisplayName() < activity.Responders[j].DisplayName()
	})
	switch {
	case len(activity.Responders) > 0 && activity.Intent != nil && activity.Observed != nil &&
		activity.Intent.Address == activity.Observed.Address:
		activity.Conclusion = "DNS Service translation occurred between the source Pod and CoreDNS boundaries"
	case activity.Intent != nil && activity.Observed != nil && activity.Intent.Address != activity.Observed.Address:
		activity.Conclusion = "DNS destination changed before the source Pod boundary"
	case activity.Intent != nil && activity.Observed != nil:
		activity.Conclusion = "DNS destination remained visible at the source Pod boundary"
	case activity.Observed != nil:
		activity.Conclusion = "DNS query observed at the source Pod boundary"
	default:
		activity.Conclusion = "DNS application intent observed; waiting for a matching packet"
	}
	return activity
}

func filterDNSQueries(observations []model.Observation, key clientKey) []model.Observation {
	filtered := make([]model.Observation, 0, len(observations))
	for _, observation := range observations {
		if observation.Protocol == key.Protocol && observation.SrcAddr == key.SourceAddr &&
			observation.SrcPort == key.SourcePort {
			filtered = append(filtered, observation)
		}
	}
	return filtered
}

func filterDNSResponses(observations []model.Observation, key clientKey) []model.Observation {
	filtered := make([]model.Observation, 0, len(observations))
	for _, observation := range observations {
		if observation.Protocol == key.Protocol && observation.DstAddr == key.SourceAddr &&
			observation.DstPort == key.SourcePort {
			filtered = append(filtered, observation)
		}
	}
	return filtered
}

func (a *Analyzer) Health() []Health {
	if a.context == nil {
		return nil
	}
	switch a.mode() {
	case model.TraceModePod:
		return []Health{
			a.healthWithLoss("source/boundary", a.packets["source"] > 0, a.ready["source"], "packet observation", "source"),
			a.healthWithLoss("destination/boundary", a.packets["destination"] > 0, a.ready["destination"], "packet observation", "destination"),
		}
	}
	source := a.ready["source"]
	backend := a.ready["backend"]
	var intent, sourceBoundary, backendBoundary, response bool
	if a.active != nil {
		intent = a.active.intent != nil
		sourceBoundary = len(a.active.sourceSYNs) > 0
		backendBoundary = a.active.backendSYN != nil
		response = a.active.response != nil
	}
	backendHealth := a.healthWithLoss("backend/boundary", backendBoundary, backend, "matching initial SYN", "backend")
	if a.active != nil && len(a.active.sourceSYNs) > 0 {
		destination := endpointFor(a.active.sourceSYNs[0], a.context)
		if a.backendUnavailable(backendBoundary, destination) {
			backendHealth = Health{
				Name: "backend/boundary", State: "UNAVAILABLE",
				Detail: "selected backend was not instrumented because it exceeds --max-backends",
			}
		}
	}
	return []Health{
		a.healthWithLoss("source/application", intent, source, "connect intent", "source"),
		a.healthWithLoss("source/boundary", sourceBoundary, source, "matching initial SYN", "source"),
		backendHealth,
		a.healthWithLoss("response", response, source, "packet from backend to source", "source"),
	}
}

func (a *Analyzer) ScopeTitle() string {
	switch a.mode() {
	case model.TraceModePod:
		return "Pod path"
	default:
		return "Service translation path"
	}
}

func (a *Analyzer) mode() model.TraceMode {
	if a.context == nil {
		return ""
	}
	if a.context.Mode != "" {
		return a.context.Mode
	}
	if a.context.Destination != nil {
		return model.TraceModePod
	}
	if a.context.Service != nil || len(a.context.Frontends) > 0 {
		return model.TraceModeService
	}
	return ""
}

func (a *Analyzer) healthWithLoss(name string, observed bool, ready model.Observation, evidence, side string) Health {
	result := health(name, observed, ready, evidence)
	if ready.Final {
		if !ready.Complete {
			result.State = "INCOMPLETE"
			result.Detail = "final capture watermark incomplete; terminal evidence may be missing"
			if observed {
				result.Detail = evidence + " observed; " + result.Detail
			}
			return result
		}
		result.Detail = fmt.Sprintf("%s; complete through sequence %d", result.Detail, ready.Sequence)
	}
	if !observed && (a.lost[side] > 0 || a.transportLost[side] > 0) {
		result.State = "INCOMPLETE"
		result.Detail = fmt.Sprintf(
			"ring-buffer loss=%d transport loss=%d",
			a.lost[side],
			a.transportLost[side],
		)
	}
	return result
}

func health(name string, observed bool, ready model.Observation, evidence string) Health {
	if observed {
		return Health{Name: name, State: "OBSERVED", Detail: evidence}
	}
	if ready.AttachmentID != "" {
		return Health{
			Name: name, State: "NO EVIDENCE",
			Detail: fmt.Sprintf("%s ifindex=%d hooks=%v", ready.Interface, ready.InterfaceIdx, ready.Hooks),
		}
	}
	return Health{Name: name, State: "NOT READY", Detail: "attachment has not reported readiness"}
}

func Relevant(observation model.Observation, context model.TraceContext) bool {
	switch observation.Kind {
	case model.KindStatus, model.KindTraceContext:
		return true
	case model.KindTransit:
		destinations := append(append([]model.Endpoint{}, context.Backends...), context.DNSFrontends...)
		destinations = append(destinations, context.DNSBackends...)
		return matchesAddress(observation.SrcAddr, []model.Endpoint{context.Source}) &&
			matchesAddress(observation.DstAddr, destinations) ||
			matchesAddress(observation.DstAddr, []model.Endpoint{context.Source}) &&
				matchesAddress(observation.SrcAddr, destinations)
	case model.KindConnect:
		return observation.Side == "source" &&
			(matchesAny(observation.DstAddr, observation.DstPort, context.Frontends) || observation.DstPort == 53)
	case model.KindPacket:
		sourceAddress := matchesAddress(observation.SrcAddr, []model.Endpoint{context.Source}) ||
			matchesAddress(observation.DstAddr, []model.Endpoint{context.Source})
		sourceIdentity := endpointIdentity(observation.SrcEndpoint, context.Source) ||
			endpointIdentity(observation.DstEndpoint, context.Source)
		targetAddress := matchesAddress(observation.SrcAddr, context.Frontends) ||
			matchesAddress(observation.DstAddr, context.Frontends) ||
			matchesAddress(observation.SrcAddr, context.Backends) ||
			matchesAddress(observation.DstAddr, context.Backends)
		dnsTraffic := observation.Side == "source" &&
			(observation.Protocol == 6 || observation.Protocol == 17) &&
			(observation.SrcPort == 53 || observation.DstPort == 53)
		dnsBackendTraffic := observation.Side == "dns" &&
			(observation.Protocol == 6 || observation.Protocol == 17) &&
			(observation.SrcPort == 53 || observation.DstPort == 53) &&
			(matchesAddress(observation.SrcAddr, context.DNSBackends) ||
				matchesAddress(observation.DstAddr, context.DNSBackends))
		return (sourceAddress || sourceIdentity) && (targetAddress || dnsTraffic || dnsBackendTraffic)
	default:
		return false
	}
}

func RelevantPodPath(observation model.Observation, context model.TraceContext) bool {
	switch observation.Kind {
	case model.KindStatus, model.KindTraceContext:
		return true
	case model.KindTransit:
		if context.Destination == nil {
			return false
		}
		return observation.SrcAddr == context.Source.Address && observation.DstAddr == context.Destination.Address ||
			observation.SrcAddr == context.Destination.Address && observation.DstAddr == context.Source.Address
	case model.KindPacket:
		if context.Destination == nil {
			return false
		}
		sourceToDestination := sourceIdentityOrAddress(observation.SrcEndpoint, observation.SrcAddr, context.Source) &&
			sourceIdentityOrAddress(observation.DstEndpoint, observation.DstAddr, *context.Destination)
		destinationToSource := sourceIdentityOrAddress(observation.SrcEndpoint, observation.SrcAddr, *context.Destination) &&
			sourceIdentityOrAddress(observation.DstEndpoint, observation.DstAddr, context.Source)
		return sourceToDestination || destinationToSource
	default:
		return false
	}
}

func endpointIdentity(endpoint *model.Endpoint, expected model.Endpoint) bool {
	return endpoint != nil && endpoint.Kind == expected.Kind &&
		endpoint.Namespace == expected.Namespace && endpoint.Name == expected.Name
}

func sourceIdentityOrAddress(endpoint *model.Endpoint, address netip.Addr, expected model.Endpoint) bool {
	return endpointIdentity(endpoint, expected) || (expected.Address.IsValid() && address == expected.Address)
}

func sourceToTarget(observation model.Observation, context model.TraceContext) bool {
	sourceMatches := matchesAddress(observation.SrcAddr, []model.Endpoint{context.Source})
	if observation.SrcEndpoint != nil {
		sourceMatches = observation.SrcEndpoint.Kind == model.EndpointPod &&
			observation.SrcEndpoint.Namespace == context.Source.Namespace &&
			observation.SrcEndpoint.Name == context.Source.Name
	}
	if !sourceMatches {
		return false
	}
	return matchesAny(observation.DstAddr, observation.DstPort, context.Frontends) ||
		matchesAddress(observation.DstAddr, context.Backends)
}

func initialSYN(observation model.Observation) bool {
	return observation.Protocol == 6 && observation.TCPFlags&0x02 != 0 && observation.TCPFlags&0x10 == 0
}

func responseFromBackend(observation model.Observation, context model.TraceContext) bool {
	return observation.Protocol == 6 &&
		matchesAddress(observation.SrcAddr, context.Backends) &&
		((observation.TCPFlags&0x12 == 0x12) || observation.TCPFlags&0x04 != 0)
}

func endpointFor(observation model.Observation, context *model.TraceContext) model.Endpoint {
	for _, endpoint := range append(append([]model.Endpoint{}, context.Frontends...), context.Backends...) {
		if endpoint.Address == observation.DstAddr && (endpoint.Port == 0 || endpoint.Port == observation.DstPort) {
			endpoint.Port = observation.DstPort
			return endpoint
		}
	}
	if observation.DstEndpoint != nil {
		return *observation.DstEndpoint
	}
	return model.Endpoint{Kind: model.EndpointIP, Address: observation.DstAddr, Port: observation.DstPort}
}

func destinationEndpoint(observation model.Observation) model.Endpoint {
	if observation.DstEndpoint != nil {
		return *observation.DstEndpoint
	}
	return model.Endpoint{Kind: model.EndpointIP, Address: observation.DstAddr, Port: observation.DstPort}
}

func matchesAny(address netip.Addr, port uint16, endpoints []model.Endpoint) bool {
	for _, endpoint := range endpoints {
		if endpoint.Address == address && (endpoint.Port == 0 || endpoint.Port == port) {
			return true
		}
	}
	return false
}

func matchesAddress(address netip.Addr, endpoints []model.Endpoint) bool {
	for _, endpoint := range endpoints {
		if endpoint.Address == address {
			return true
		}
	}
	return false
}

func EndpointLine(endpoint model.Endpoint) string {
	name := endpoint.DisplayName()
	if endpoint.Address.IsValid() && endpoint.Port != 0 {
		return fmt.Sprintf("%s (%s) [%s]:%d", name, endpoint.Kind, endpoint.Address, endpoint.Port)
	}
	if endpoint.Address.IsValid() {
		return fmt.Sprintf("%s (%s) [%s]", name, endpoint.Kind, endpoint.Address)
	}
	return fmt.Sprintf("%s (%s)", name, endpoint.Kind)
}
