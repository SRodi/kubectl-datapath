package tui

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/SRodi/kubectl-datapath/internal/flow"
	"github.com/SRodi/kubectl-datapath/internal/model"
	traceview "github.com/SRodi/kubectl-datapath/internal/trace"
)

type observationMsg struct {
	observation model.Observation
}

type streamClosedMsg struct {
	err error
}

type streamErrorMsg struct {
	err error
}

type Model struct {
	title            string
	observations     <-chan model.Observation
	errors           <-chan error
	tracker          *flow.Tracker
	trace            *traceview.Analyzer
	packets          map[flow.Key][]model.Observation
	tracePackets     map[string][]model.Observation
	traceContext     *model.TraceContext
	activeTraceFlow  string
	activeTraceSeen  time.Time
	activeFlow       flow.Key
	activeFlowSeen   time.Time
	hasActiveFlow    bool
	evidenceCounts   map[model.Kind]uint64
	lostByAttachment map[string]uint64
	showDetails      bool
	viewOffset       int
	followView       bool
	width            int
	height           int
	closed           bool
	err              error
}

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("229"))
	warnStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	subtleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	exactStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	relatedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
)

func New(title string, observations <-chan model.Observation, errors <-chan error) Model {
	return Model{
		title:            title,
		observations:     observations,
		errors:           errors,
		tracker:          flow.NewTracker(),
		trace:            traceview.NewAnalyzer(),
		packets:          make(map[flow.Key][]model.Observation),
		tracePackets:     make(map[string][]model.Observation),
		evidenceCounts:   make(map[model.Kind]uint64),
		lostByAttachment: make(map[string]uint64),
	}
}

func (m Model) Init() tea.Cmd {
	return waitForStream(m.observations, m.errors)
}

func waitForStream(observations <-chan model.Observation, errors <-chan error) tea.Cmd {
	return func() tea.Msg {
		for {
			select {
			case observation, ok := <-observations:
				if !ok {
					return streamClosedMsg{}
				}
				return observationMsg{observation: observation}
			case err, ok := <-errors:
				if !ok {
					errors = nil
					continue
				}
				if err != nil {
					return streamErrorMsg{err: err}
				}
			}
		}
	}
}

func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.KeyMsg:
		switch message.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "d":
			m.showDetails = !m.showDetails
			m.clampViewOffset()
		case "j", "down":
			m.followView = false
			m.viewOffset++
			m.clampViewOffset()
		case "k", "up":
			m.followView = false
			m.viewOffset--
			m.clampViewOffset()
		case "g", "home":
			m.followView = false
			m.viewOffset = 0
		case "G", "end":
			m.followView = true
			m.viewOffset = m.maxViewOffset()
		case "pgdown":
			m.followView = false
			m.viewOffset += m.viewPageStep()
			m.clampViewOffset()
		case "pgup":
			m.followView = false
			m.viewOffset -= m.viewPageStep()
			m.clampViewOffset()
		}
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		if m.followView {
			m.viewOffset = m.maxViewOffset()
		} else {
			m.clampViewOffset()
		}
	case observationMsg:
		switch message.observation.Kind {
		case model.KindPacket, model.KindTransit, model.KindConnect:
			m.evidenceCounts[message.observation.Kind]++
		}
		attachment := message.observation.AttachmentID
		if attachment == "" {
			attachment = message.observation.Side
		}
		if message.observation.Lost > m.lostByAttachment[attachment] {
			m.lostByAttachment[attachment] = message.observation.Lost
		}
		m.tracker.Observe(message.observation)
		m.trace.Observe(message.observation)
		switch message.observation.Kind {
		case model.KindTraceContext:
			initialContext := m.traceContext == nil
			m.traceContext = message.observation.Trace
			if initialContext {
				m.viewOffset = 0
				m.followView = false
			}
		case model.KindPacket:
			key := flow.NewKey(message.observation)
			m.packets[key] = append(m.packets[key], message.observation)
			if m.traceContext != nil {
				if m.traceContext.Mode == model.TraceModeService &&
					!serviceAttemptPacket(message.observation, *m.traceContext) {
					if m.followView {
						m.viewOffset = m.maxViewOffset()
					}
					return m, waitForStream(m.observations, m.errors)
				}
				traceKey := traceConnectionKey(message.observation, *m.traceContext)
				if traceKey != "" {
					m.tracePackets[traceKey] = append(m.tracePackets[traceKey], message.observation)
					if m.traceContext.Mode == model.TraceModeService {
						attempts := m.trace.Attempts()
						if len(attempts) > 0 {
							active := attempts[0]
							activeKey := attemptDisplayKey(
								active.Protocol, active.SourceAddr, active.SourcePort, active.InitialSequence,
							)
							if activeKey != m.activeTraceFlow {
								m.activeTraceFlow = activeKey
								m.viewOffset = 0
								m.followView = false
							}
							m.activeTraceSeen = active.Started
						}
					} else if m.activeTraceFlow == "" || message.observation.WallTime.After(m.activeTraceSeen) {
						if traceKey != m.activeTraceFlow {
							m.activeTraceFlow = traceKey
							m.viewOffset = 0
							m.followView = false
						}
						m.activeTraceSeen = message.observation.WallTime
					}
				}
			} else if !m.hasActiveFlow || message.observation.WallTime.After(m.activeFlowSeen) {
				if !m.hasActiveFlow || key != m.activeFlow {
					m.activeFlow = key
					m.hasActiveFlow = true
					m.viewOffset = 0
					m.followView = false
				}
				m.activeFlowSeen = message.observation.WallTime
			}
			if m.followView {
				m.viewOffset = m.maxViewOffset()
			}
		}
		return m, waitForStream(m.observations, m.errors)
	case streamClosedMsg:
		m.closed = true
		if message.err != nil {
			m.err = message.err
		}
	case streamErrorMsg:
		m.err = message.err
		return m, waitForStream(m.observations, m.errors)
	}
	return m, nil
}

func (m Model) View() string {
	content := m.renderContent()
	if m.height <= 0 {
		return content + "\n" + m.helpLine(1, lineCount(content))
	}
	lines := strings.Split(content, "\n")
	pageSize := m.viewPageSize()
	maxOffset := max(0, len(lines)-pageSize)
	offset := min(max(m.viewOffset, 0), maxOffset)
	end := min(offset+pageSize, len(lines))
	return strings.Join(lines[offset:end], "\n") + "\n" + m.helpLine(offset+1, end)
}

func (m Model) renderContent() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s\n", titleStyle.Render("kubectl-datapath · "+m.title))

	flows := m.tracker.Flows()
	attempts := m.trace.Attempts()
	serviceTrace := m.trace.IsServiceTrace()
	var lost uint64
	for _, current := range m.lostByAttachment {
		lost += current
	}
	status := "observing"
	if m.closed {
		status = "complete"
	}
	if serviceTrace {
		fmt.Fprintf(&builder, "%s  Attempts %d  Boundary %d  Transit %d  Connect %d  Lost %d\n\n",
			subtleStyle.Render("Status "+status), len(attempts),
			m.evidenceCounts[model.KindPacket], m.evidenceCounts[model.KindTransit],
			m.evidenceCounts[model.KindConnect], lost)
	} else {
		fmt.Fprintf(&builder, "%s  Flows %d  Boundary %d  Transit %d  Connect %d  Lost %d\n\n",
			subtleStyle.Render("Status "+status), len(flows),
			m.evidenceCounts[model.KindPacket], m.evidenceCounts[model.KindTransit],
			m.evidenceCounts[model.KindConnect], lost)
	}

	datapath := m.trace.Datapath()
	if datapath != nil {
		renderDatapath(&builder, *datapath)
	}

	stages := m.trace.Stages()
	if len(stages) > 0 && m.showDetails {
		builder.WriteString(headerStyle.Render(m.trace.ScopeTitle()) + "\n")
		for _, stage := range stages {
			fmt.Fprintf(&builder, "  %-22s %s\n", stage.Name, endpointLine(stage.Endpoint))
			fmt.Fprintf(&builder, "  %-22s %s\n", "", subtleStyle.Render(stage.Detail))
		}
		builder.WriteString("  " + warnStyle.Render(m.trace.Conclusion()) + "\n\n")
		builder.WriteString(headerStyle.Render("Trace evidence") + "\n")
		for _, health := range m.trace.Health() {
			style := exactStyle
			if health.State != "OBSERVED" {
				style = warnStyle
			}
			fmt.Fprintf(&builder, "  %-22s %-12s %s\n", health.Name, style.Render(health.State), subtleStyle.Render(health.Detail))
		}
		builder.WriteString("\n")
		if transit := m.trace.Transit(); transit != nil {
			renderTransitDetails(&builder, transit, datapath)
		}
	}
	if len(stages) > 0 && !m.showDetails {
		builder.WriteString(subtleStyle.Render("Detailed path, health, and transit evidence hidden · press d to expand") + "\n\n")
	}
	if serviceTrace {
		renderAttempts(&builder, attempts, datapath)
	}
	if dns := m.trace.DNS(); dns != nil {
		renderDNS(&builder, dns)
	}

	if !serviceTrace {
		builder.WriteString(headerStyle.Render("Flows") + "\n")
		if len(flows) == 0 {
			builder.WriteString(subtleStyle.Render("  waiting for packet observations…") + "\n")
		}
		for index, current := range flows {
			if index >= 6 {
				break
			}
			statusStyle := exactStyle
			if current.Status == flow.StatusIncomplete {
				statusStyle = warnStyle
			}
			name := current.Key.String()
			if current.SourceEndpoint != nil || current.DestEndpoint != nil {
				name = endpointPair(current.SourceEndpoint, current.DestEndpoint, current.Key.String())
			}
			fmt.Fprintf(&builder, "  %-58s %s\n", truncate(name, 58), statusStyle.Render(string(current.Status)))
		}
	}

	rows, packetCount, multipleNodes := m.packetRows()
	title := "Current flow observations · chronological"
	if serviceTrace {
		if datapath != nil && datapath.AttemptSuperseded {
			title = "Latest backend attempt observations · historical · chronological"
		} else {
			title = "Current attempt observations · chronological"
		}
	}
	if multipleNodes {
		if serviceTrace {
			if datapath != nil && datapath.AttemptSuperseded {
				title = "Latest backend attempt observations · historical · node-local chronology"
			} else {
				title = "Current attempt observations · node-local chronology"
			}
		} else {
			title = "Current flow observations · node-local chronology"
		}
	}
	if len(rows) > 0 {
		title += fmt.Sprintf(" · showing 1-%d of %d observations", packetCount, packetCount)
	} else {
		title += " · waiting for observations"
	}
	builder.WriteString("\n" + headerStyle.Render(title) + "\n")
	for _, row := range rows {
		if row.header != "" {
			builder.WriteString("  " + subtleStyle.Render(row.header) + "\n")
			continue
		}
		builder.WriteString(renderPacket(*row.observation) + "\n")
	}
	if m.err != nil {
		builder.WriteString("\n" + warnStyle.Render("stream error: "+m.err.Error()) + "\n")
	}
	return strings.TrimSuffix(builder.String(), "\n")
}

func renderDatapath(builder *strings.Builder, datapath traceview.DatapathView) {
	builder.WriteString(headerStyle.Render("Datapath evidence") + "\n")
	if datapath.Focus != "" {
		fmt.Fprintf(builder, "  Latest focus: %s\n", datapath.Focus)
		if datapath.FocusDetail != "" {
			builder.WriteString("                " + subtleStyle.Render(datapath.FocusDetail) + "\n")
		}
	}
	sourceNode := datapath.SourceNode
	if sourceNode == "" {
		sourceNode = "unknown node"
	}
	destinationNode := datapath.DestinationNode
	if destinationNode == "" {
		destinationNode = "unresolved backend node"
	}
	fmt.Fprintf(builder, "  srcNode: %s\n", sourceNode)
	fmt.Fprintf(builder, "    [srcPodNetNS: %s]\n", truncate(datapath.Source.DisplayName(), 36))
	if datapath.Connect != nil {
		fmt.Fprintf(builder, "       %s %s: %s\n",
			captureMarker(*datapath.Connect), datapath.ConnectKind, truncate(datapath.ConnectLabel, 36))
	}
	sourceHost := "srcHostNetNS"
	destinationHost := "dstHostNetNS"
	if !datapath.CrossNode {
		sourceHost = "hostNetNS"
		destinationHost = "hostNetNS"
	}
	fmt.Fprintf(builder, "       └──%s source veth──> [%s]\n", captureMarker(datapath.SourceBoundary), sourceHost)
	if datapath.CrossNode {
		fmt.Fprintf(builder, "  transit: [srcHostNetNS] ──%s── %s ──%s──> [dstHostNetNS]\n",
			captureMarker(dereferencePoint(datapath.SourceTransit)),
			datapath.TransitLabel,
			captureMarker(dereferencePoint(datapath.DestinationTransit)),
		)
	} else {
		builder.WriteString("  host: shared host network namespace\n")
	}
	fmt.Fprintf(builder, "  dstNode: %s\n", destinationNode)
	fmt.Fprintf(builder, "    [%s] ──%s to destination Pod (host veth)──> [dstPodNetNS: %s]\n",
		destinationHost,
		captureMarker(datapath.DestinationBoundary),
		truncate(datapath.Destination.DisplayName(), 36),
	)
	builder.WriteString("  " + subtleStyle.Render("● observed  × attached, no matching evidence  ! incomplete  ○ not ready/unavailable") + "\n\n")
	diagnosisStyle := exactStyle
	if strings.Contains(datapath.Diagnosis, "gap") || strings.Contains(datapath.Diagnosis, "incomplete") {
		diagnosisStyle = warnStyle
	}
	builder.WriteString(headerStyle.Render("Diagnosis") + "\n")
	builder.WriteString("  " + diagnosisStyle.Render(datapath.Diagnosis) + "\n\n")
	if len(datapath.Policies) > 0 {
		builder.WriteString(headerStyle.Render("Relevant configuration") + "\n")
		for _, policy := range datapath.Policies {
			mode := policy.Scope
			if policy.DenyAll {
				mode += " deny-all"
			}
			fmt.Fprintf(builder, "  NetworkPolicy %s/%s · %s · selects %s\n",
				policy.Namespace, policy.Name, mode, strings.Join(policy.Pods, ", "))
		}
		builder.WriteString("  " + subtleStyle.Render("Configuration context only; this is not a packet-drop verdict.") + "\n\n")
	}
}

func renderTransitDetails(
	builder *strings.Builder,
	transit *traceview.TransitActivity,
	datapath *traceview.DatapathView,
) {
	builder.WriteString(headerStyle.Render("Node transit") + "\n")
	health := append([]traceview.Health(nil), transit.Attachments...)
	sourceNode := ""
	destinationNode := ""
	if datapath != nil {
		sourceNode = datapath.SourceNode
		destinationNode = datapath.DestinationNode
	}
	sort.SliceStable(health, func(i, j int) bool {
		return nodeOrder(health[i].Name, sourceNode, destinationNode) <
			nodeOrder(health[j].Name, sourceNode, destinationNode)
	})
	for _, current := range health {
		style := exactStyle
		if current.State != "OBSERVED" {
			style = warnStyle
		}
		fmt.Fprintf(builder, "  %-22s %-12s %s\n",
			current.Name, style.Render(current.State), subtleStyle.Render(current.Detail))
	}
	byNode := make(map[string][]model.Observation)
	for _, observation := range transit.Observations {
		byNode[observation.Node] = append(byNode[observation.Node], observation)
	}
	nodes := make([]string, 0, len(byNode))
	for node := range byNode {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodeOrder(nodes[i], sourceNode, destinationNode) <
			nodeOrder(nodes[j], sourceNode, destinationNode)
	})
	for _, node := range nodes {
		label := "node"
		if node == sourceNode {
			label = "source node"
		} else if node == destinationNode {
			label = "destination node"
		}
		builder.WriteString("  " + subtleStyle.Render(label+" "+node+" · monotonic order") + "\n")
		for _, observation := range byNode[node] {
			builder.WriteString(renderTransit(observation) + "\n")
		}
	}
	builder.WriteString("  " + subtleStyle.Render(transit.Conclusion) + "\n\n")
}

func nodeOrder(value, sourceNode, destinationNode string) string {
	switch {
	case sourceNode != "" && strings.Contains(value, sourceNode):
		return "0/" + value
	case destinationNode != "" && strings.Contains(value, destinationNode):
		return "1/" + value
	default:
		return "2/" + value
	}
}

func renderDNS(builder *strings.Builder, dns *traceview.DNSActivity) {
	builder.WriteString(headerStyle.Render("DNS exchange") + "\n")
	if dns.Intent != nil {
		fmt.Fprintf(builder, "  %-22s %s\n", "Application intent", endpointLine(*dns.Intent))
	}
	if dns.Observed != nil {
		fmt.Fprintf(builder, "  %-22s %s\n", "Source Pod boundary", endpointLine(*dns.Observed))
	}
	for _, responder := range dns.Responders {
		fmt.Fprintf(builder, "  %-22s %s\n", "CoreDNS responder", endpointLine(responder))
	}
	fmt.Fprintf(builder, "  %-22s queries=%d responses=%d\n", "Source boundary", dns.Queries, dns.Responses)
	if dns.BackendQueries > 0 || dns.BackendResponses > 0 {
		fmt.Fprintf(builder, "  %-22s queries=%d responses=%d\n",
			"CoreDNS boundary", dns.BackendQueries, dns.BackendResponses)
	}
	builder.WriteString("  " + subtleStyle.Render(dns.Conclusion) + "\n")
	dnsObservations := append(append([]model.Observation{}, dns.Observations...), dns.BackendObservations...)
	rows, _, multipleNodes := packetRowsFor(dnsObservations)
	if multipleNodes {
		builder.WriteString("  " + subtleStyle.Render("node-local chronology") + "\n")
	}
	for _, row := range rows {
		if row.header != "" {
			builder.WriteString("  " + subtleStyle.Render(row.header) + "\n")
			continue
		}
		builder.WriteString(renderPacket(*row.observation) + "\n")
	}
	builder.WriteString("\n")
}

func dereferencePoint(point *traceview.EvidencePoint) traceview.EvidencePoint {
	if point == nil {
		return traceview.EvidencePoint{State: "NOT READY"}
	}
	return *point
}

func captureMarker(point traceview.EvidencePoint) string {
	switch point.State {
	case "OBSERVED":
		return exactStyle.Render("●")
	case "NO EVIDENCE":
		return warnStyle.Render("×")
	case "INCOMPLETE":
		return warnStyle.Render("!")
	default:
		return subtleStyle.Render("○")
	}
}

func renderAttempts(
	builder *strings.Builder,
	attempts []traceview.AttemptSummary,
	datapath *traceview.DatapathView,
) {
	title := "Current attempt"
	if datapath != nil && datapath.AttemptSuperseded {
		title = "Latest backend attempt · historical"
	}
	builder.WriteString(headerStyle.Render(title) + "\n")
	if len(attempts) == 0 {
		builder.WriteString(subtleStyle.Render("  waiting for an initial TCP SYN…") + "\n\n")
		return
	}
	current := attempts[0]
	style := warnStyle
	if current.ResponseObserved {
		style = exactStyle
	}
	fmt.Fprintf(builder, "  %s  client :%-5d  %s\n\n",
		current.Started.Format("15:04:05.000000"), current.SourcePort, style.Render(current.Status))
	if datapath != nil && datapath.AttemptSuperseded {
		builder.WriteString("  " + subtleStyle.Render("Newer unresolved DNS evidence supersedes this backend attempt.") + "\n\n")
	}
	if len(attempts) == 1 {
		return
	}
	builder.WriteString(headerStyle.Render("Previous attempts") + "\n")
	limit := min(len(attempts), 6)
	for _, previous := range attempts[1:limit] {
		statusStyle := subtleStyle
		if !previous.ResponseObserved {
			statusStyle = warnStyle
		}
		fmt.Fprintf(builder, "  %s  client :%-5d  %s\n",
			previous.Started.Format("15:04:05.000000"), previous.SourcePort, statusStyle.Render(previous.Status))
	}
	if len(attempts) > limit {
		fmt.Fprintf(builder, "  %s\n", subtleStyle.Render(fmt.Sprintf("%d older attempts not shown", len(attempts)-limit)))
	}
	builder.WriteString("\n")
}

type packetRow struct {
	header      string
	observation *model.Observation
}

func (m Model) currentPackets() []model.Observation {
	if m.traceContext != nil {
		return append([]model.Observation(nil), m.tracePackets[m.activeTraceFlow]...)
	}
	if !m.hasActiveFlow {
		return nil
	}
	return append([]model.Observation(nil), m.packets[m.activeFlow]...)
}

func traceConnectionKey(observation model.Observation, context model.TraceContext) string {
	if context.Mode != model.TraceModeService {
		if sourceEndpoint(observation.SrcEndpoint, observation.SrcAddr, context.Source) {
			return fmt.Sprintf("%d/%s/%d", observation.Protocol, observation.SrcAddr, observation.SrcPort)
		}
		if sourceEndpoint(observation.DstEndpoint, observation.DstAddr, context.Source) {
			return fmt.Sprintf("%d/%s/%d", observation.Protocol, observation.DstAddr, observation.DstPort)
		}
		return ""
	}
	if sourceEndpoint(observation.SrcEndpoint, observation.SrcAddr, context.Source) &&
		observation.Protocol == 6 && observation.TCPFlags&0x02 != 0 && observation.TCPFlags&0x10 == 0 {
		return attemptDisplayKey(
			observation.Protocol, observation.SrcAddr, observation.SrcPort, observation.TCPSequence,
		)
	}
	if sourceEndpoint(observation.DstEndpoint, observation.DstAddr, context.Source) &&
		observation.Protocol == 6 && observation.TCPFlags&0x10 != 0 && observation.TCPAck != 0 {
		return attemptDisplayKey(
			observation.Protocol, observation.DstAddr, observation.DstPort, observation.TCPAck-1,
		)
	}
	return ""
}

func attemptDisplayKey(protocol uint8, source netip.Addr, sourcePort uint16, initialSequence uint32) string {
	return fmt.Sprintf("%d/%s/%d/%d", protocol, source, sourcePort, initialSequence)
}

func serviceAttemptPacket(observation model.Observation, context model.TraceContext) bool {
	if observation.Protocol != 6 {
		return false
	}
	sourceMatches := sourceEndpoint(observation.SrcEndpoint, observation.SrcAddr, context.Source) ||
		sourceEndpoint(observation.DstEndpoint, observation.DstAddr, context.Source)
	if !sourceMatches {
		return false
	}
	return endpointAddressMatches(observation.SrcAddr, context.Frontends) ||
		endpointAddressMatches(observation.DstAddr, context.Frontends) ||
		endpointAddressMatches(observation.SrcAddr, context.Backends) ||
		endpointAddressMatches(observation.DstAddr, context.Backends)
}

func endpointAddressMatches(address interface{ String() string }, endpoints []model.Endpoint) bool {
	for _, endpoint := range endpoints {
		if endpoint.Address.IsValid() && endpoint.Address.String() == address.String() {
			return true
		}
	}
	return false
}

func sourceEndpoint(endpoint *model.Endpoint, address interface{ String() string }, expected model.Endpoint) bool {
	if endpoint != nil {
		return endpoint.Kind == expected.Kind && endpoint.Namespace == expected.Namespace && endpoint.Name == expected.Name
	}
	return expected.Address.IsValid() && address.String() == expected.Address.String()
}

func (m Model) packetRows() ([]packetRow, int, bool) {
	return packetRowsFor(m.currentPackets())
}

func packetRowsFor(packets []model.Observation) ([]packetRow, int, bool) {
	if len(packets) == 0 {
		return nil, 0, false
	}
	byNode := make(map[string][]model.Observation)
	for _, observation := range packets {
		node := observation.Node
		if node == "" {
			node = "unknown"
		}
		byNode[node] = append(byNode[node], observation)
	}
	nodes := make([]string, 0, len(byNode))
	for node := range byNode {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	multipleNodes := len(nodes) > 1
	rows := make([]packetRow, 0, len(packets)+len(nodes))
	for _, node := range nodes {
		current := byNode[node]
		sort.SliceStable(current, func(i, j int) bool {
			return observationBefore(current[i], current[j])
		})
		if multipleNodes {
			rows = append(rows, packetRow{header: "node " + node + " · monotonic order"})
		}
		for index := range current {
			observation := current[index]
			rows = append(rows, packetRow{observation: &observation})
		}
	}
	return rows, len(packets), multipleNodes
}

func observationBefore(left, right model.Observation) bool {
	if left.MonotonicNS != 0 && right.MonotonicNS != 0 && left.MonotonicNS != right.MonotonicNS {
		return left.MonotonicNS < right.MonotonicNS
	}
	if !left.WallTime.Equal(right.WallTime) {
		return left.WallTime.Before(right.WallTime)
	}
	if left.AttachmentID != right.AttachmentID {
		return left.AttachmentID < right.AttachmentID
	}
	return left.Sequence < right.Sequence
}

func renderPacket(observation model.Observation) string {
	confidence := exactStyle.Render(string(observation.Confidence))
	if observation.Confidence == model.ConfidenceRelated || observation.Confidence == model.ConfidenceUnattributed {
		confidence = relatedStyle.Render(string(observation.Confidence))
	}
	return fmt.Sprintf("  %s %-7s %-9s %-15s %5dB  %s → %s  %s",
		observation.WallTime.Format("15:04:05.000000"),
		observation.Side,
		podDirection(observation),
		observation.PacketName(),
		observation.PacketLength,
		displayEndpoint(observation.SrcEndpoint, observation.SrcAddr, observation.SrcPort),
		displayEndpoint(observation.DstEndpoint, observation.DstAddr, observation.DstPort),
		confidence,
	)
}

func renderTransit(observation model.Observation) string {
	inner := fmt.Sprintf("%s:%d → %s:%d",
		observation.SrcAddr, observation.SrcPort, observation.DstAddr, observation.DstPort)
	transport := string(observation.Encapsulation)
	if observation.Encapsulation == model.EncapsulationVXLAN {
		transport = fmt.Sprintf("VXLAN vni=%d %s:%d → %s:%d",
			observation.TunnelID,
			observation.OuterSrcAddr, observation.OuterSrcPort,
			observation.OuterDstAddr, observation.OuterDstPort,
		)
	} else if observation.Encapsulation == model.EncapsulationNative {
		transport = "native routing"
	}
	return fmt.Sprintf("  %s %-20s %-7s %-8s  %s  inner %s",
		observation.WallTime.Format("15:04:05.000000"),
		truncate(observation.Node+"/"+observation.Interface, 20),
		observation.Direction,
		model.ProtocolName(observation.Protocol),
		transport,
		inner,
	)
}

func (m Model) viewPageSize() int {
	if m.height <= 1 {
		return 1
	}
	return m.height - 1
}

func (m Model) viewPageStep() int {
	return max(1, m.viewPageSize()-2)
}

func (m Model) maxViewOffset() int {
	return max(0, lineCount(m.renderContent())-m.viewPageSize())
}

func (m *Model) clampViewOffset() {
	m.viewOffset = max(0, min(m.viewOffset, m.maxViewOffset()))
}

func (m Model) helpLine(start, end int) string {
	total := lineCount(m.renderContent())
	position := fmt.Sprintf("lines %d-%d of %d", start, end, total)
	return subtleStyle.Render("[j/k] scroll  [g/G] first/last  [d] details  [q] quit  " + position + "  evidence, not delivery verdicts")
}

func lineCount(value string) int {
	if value == "" {
		return 0
	}
	return strings.Count(value, "\n") + 1
}

func endpointLine(endpoint model.Endpoint) string {
	return traceview.EndpointLine(endpoint)
}

func endpointPair(source, destination *model.Endpoint, fallback string) string {
	if source == nil && destination == nil {
		return fallback
	}
	var sourceName, destinationName string
	if source != nil {
		sourceName = endpointNameWithPort(*source)
	}
	if destination != nil {
		destinationName = endpointNameWithPort(*destination)
	}
	if sourceName == "" || destinationName == "" {
		return fallback
	}
	return sourceName + " ↔ " + destinationName
}

func endpointNameWithPort(endpoint model.Endpoint) string {
	if endpoint.Port == 0 {
		return endpoint.DisplayName()
	}
	return fmt.Sprintf("%s:%d", endpoint.DisplayName(), endpoint.Port)
}

func podDirection(observation model.Observation) string {
	if !strings.Contains(observation.Point, "veth") {
		return string(observation.Direction)
	}
	switch observation.Direction {
	case model.DirectionIngress:
		return "from-pod"
	case model.DirectionEgress:
		return "to-pod"
	default:
		return "unknown"
	}
}

func displayEndpoint(endpoint *model.Endpoint, address interface{ String() string }, port uint16) string {
	if endpoint != nil {
		name := endpoint.DisplayName()
		if port != 0 {
			return fmt.Sprintf("%s [%s]:%d", name, address.String(), port)
		}
		return fmt.Sprintf("%s [%s]", name, address.String())
	}
	if port != 0 {
		return fmt.Sprintf("%s:%d", address.String(), port)
	}
	return address.String()
}

func truncate(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width < 2 {
		return value[:width]
	}
	return value[:width-1] + "…"
}

func Run(ctx context.Context, title string, observations <-chan model.Observation, errors <-chan error, input io.Reader, output io.Writer) error {
	options := []tea.ProgramOption{tea.WithContext(ctx), tea.WithOutput(output)}
	if input != nil {
		options = append(options, tea.WithInput(input))
	}
	_, err := tea.NewProgram(New(title, observations, errors), options...).Run()
	return err
}
