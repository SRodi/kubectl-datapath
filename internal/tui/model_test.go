package tui

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/SRodi/kubectl-datapath/internal/model"
	traceview "github.com/SRodi/kubectl-datapath/internal/trace"
)

func TestViewShowsHonestStatus(t *testing.T) {
	observations := make(chan model.Observation, 1)
	errors := make(chan error, 1)
	m := New("test", observations, errors)
	updated, _ := m.Update(observationMsg{observation: model.Observation{
		SchemaVersion: model.SchemaVersion,
		Kind:          model.KindPacket,
		WallTime:      time.Now(),
		Protocol:      6,
		SrcAddr:       netip.MustParseAddr("10.0.0.1"),
		DstAddr:       netip.MustParseAddr("10.0.0.2"),
		SrcPort:       1234,
		DstPort:       80,
		PacketLength:  136,
		TCPFlags:      0x18,
		Point:         "host-veth/tcx",
		Direction:     model.DirectionIngress,
		Confidence:    model.ConfidenceExact,
		SrcEndpoint: &model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "frontend",
			Address: netip.MustParseAddr("10.0.0.1"), Port: 1234,
		},
		DstEndpoint: &model.Endpoint{
			Kind: model.EndpointService, Namespace: "demo", Name: "api",
			Address: netip.MustParseAddr("10.0.0.2"), Port: 80,
		},
	}})
	view := updated.(Model).View()
	if !strings.Contains(view, "traffic observed") || strings.Contains(view, "delivered") {
		t.Fatalf("unexpected view:\n%s", view)
	}
	if !strings.Contains(view, "frontend.demo") || !strings.Contains(view, "api.demo") {
		t.Fatalf("endpoint names missing from view:\n%s", view)
	}
	for _, expected := range []string{"frontend.demo:1234", "api.demo:80", "from-pod", "PSH-ACK", "136B"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("%q missing from view:\n%s", expected, view)
		}
	}
}

func TestTraceConnectionKeySeparatesReusedClientPorts(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.10")
	backend := netip.MustParseAddr("10.0.1.20")
	context := model.TraceContext{
		Mode: model.TraceModeService,
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "frontend", Address: source,
		},
	}
	first := model.Observation{
		Protocol: 6, SrcAddr: source, DstAddr: backend, SrcPort: 40000, DstPort: 80,
		TCPFlags: 0x02, TCPSequence: 100,
	}
	second := first
	second.TCPSequence = 200
	response := model.Observation{
		Protocol: 6, SrcAddr: backend, DstAddr: source, SrcPort: 80, DstPort: 40000,
		TCPFlags: 0x12, TCPAck: 201,
	}

	firstKey := traceConnectionKey(first, context)
	secondKey := traceConnectionKey(second, context)
	if firstKey == secondKey {
		t.Fatalf("reused client port merged attempts: %q", firstKey)
	}
	if responseKey := traceConnectionKey(response, context); responseKey != secondKey {
		t.Fatalf("response key = %q, want %q", responseKey, secondKey)
	}
}

func TestActiveAttemptPacketKeyIncludesEstablishedTraffic(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.10")
	backend := netip.MustParseAddr("10.0.1.20")
	context := model.TraceContext{
		Mode: model.TraceModeService,
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "frontend", Address: source,
		},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "demo", Name: "backend", Address: backend,
		}},
	}
	attempts := []traceview.AttemptSummary{{
		Protocol: 6, SourceAddr: source, SourcePort: 40000, InitialSequence: 100, Active: true,
	}}
	request := model.Observation{
		Protocol: 6, SrcAddr: source, DstAddr: backend, SrcPort: 40000, DstPort: 80,
		TCPFlags: 0x18, TCPSequence: 101, TCPAck: 500,
	}
	response := model.Observation{
		Protocol: 6, SrcAddr: backend, DstAddr: source, SrcPort: 80, DstPort: 40000,
		TCPFlags: 0x18, TCPSequence: 500, TCPAck: 140,
	}
	expected := attemptDisplayKey(6, source, 40000, 100)
	for _, observation := range []model.Observation{request, response} {
		if key := activeAttemptPacketKey(observation, context, attempts); key != expected {
			t.Fatalf("established packet key = %q, want %q", key, expected)
		}
	}
}

func TestViewShowsServiceTranslationPath(t *testing.T) {
	observations := make(chan model.Observation, 1)
	errors := make(chan error, 1)
	m := New("trace", observations, errors)
	context := model.TraceContext{
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "frontend",
			Address: netip.MustParseAddr("fd00:10::10"),
		},
		Service: &model.Endpoint{Kind: model.EndpointService, Namespace: "demo", Name: "api"},
		Frontends: []model.Endpoint{{
			Kind: model.EndpointService, Namespace: "demo", Name: "api",
			Address: netip.MustParseAddr("fd00:96::10"), Port: 443,
		}},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "demo", Name: "api-abc",
			Address: netip.MustParseAddr("fd00:10::20"), Port: 8443,
		}},
	}
	now := time.Now()
	events := []model.Observation{
		{Kind: model.KindTraceContext, Trace: &context},
		{
			Kind: model.KindConnect, Side: "source", WallTime: now,
			DstAddr: context.Frontends[0].Address, DstPort: 443, Confidence: model.ConfidenceExact,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Millisecond),
			SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			Protocol: 6, SrcPort: 40000, DstPort: 8443, TCPFlags: 0x02, TCPSequence: 100,
			Confidence: model.ConfidenceExact,
		},
		{
			Kind: model.KindPacket, Side: "backend", WallTime: now.Add(2 * time.Millisecond),
			SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			Protocol: 6, SrcPort: 40000, DstPort: 8443, TCPFlags: 0x02, TCPSequence: 100,
			Confidence: model.ConfidenceExact,
		},
	}
	var current tea.Model = m
	for _, event := range events {
		current, _ = current.Update(observationMsg{observation: event})
	}
	current, _ = current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	view := current.(Model).View()
	if !strings.Contains(view, "Service translation path") ||
		!strings.Contains(view, "before the source Pod boundary") ||
		!strings.Contains(view, "fd00:96::10") {
		t.Fatalf("unexpected trace view:\n%s", view)
	}
}

func TestDatapathVisualizationMarksMissingBackendEvidence(t *testing.T) {
	observations := make(chan model.Observation)
	errors := make(chan error)
	m := New("trace", observations, errors)
	context := model.TraceContext{
		Mode: model.TraceModeService,
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "frontend",
			Node: "worker-a", Address: netip.MustParseAddr("10.244.0.5"),
		},
		Service: &model.Endpoint{Kind: model.EndpointService, Namespace: "demo", Name: "backend"},
		Frontends: []model.Endpoint{{
			Kind: model.EndpointService, Namespace: "demo", Name: "backend",
			Address: netip.MustParseAddr("10.96.0.20"), Port: 80,
		}},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "demo", Name: "backend-abc",
			Node: "worker-a", Address: netip.MustParseAddr("10.244.0.8"), Port: 80,
		}},
		Policies: []model.PolicyContext{{
			Namespace: "demo", Name: "deny-all-backend", Scope: "destination ingress",
			Pods: []string{"backend-abc"}, DenyAll: true,
		}},
	}

	events := []model.Observation{
		{Kind: model.KindTraceContext, Trace: &context},
		{Kind: model.KindStatus, Side: "source", AttachmentID: "source", Node: "worker-a", Interface: "veth-source"},
		{Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1", Node: "worker-a", Interface: "veth-backend"},
		{
			Kind: model.KindPacket, Side: "source", WallTime: time.Now(),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
		},
	}
	var current tea.Model = m
	for _, event := range events {
		current, _ = current.Update(observationMsg{observation: event})
	}
	view := current.(Model).View()
	for _, expected := range []string{
		"Datapath evidence",
		"● source veth",
		"× to destination Pod",
		"× connect intent",
		"shared host network namespace",
		"Detailed path, health, and transit evidence hidden",
		"NetworkPolicy demo/deny-all-backend",
		"destination ingress deny-all",
		"not a packet-drop verdict",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("%q missing from datapath view:\n%s", expected, view)
		}
	}
}

func TestDatapathVisualizationShowsObservedBackendDespiteCoverageMetadata(t *testing.T) {
	observations := make(chan model.Observation)
	errors := make(chan error)
	m := New("trace", observations, errors)
	context := model.TraceContext{
		Mode: model.TraceModeService,
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "default", Name: "frontend",
			Node: "worker-a", Address: netip.MustParseAddr("10.0.1.5"),
		},
		Service: &model.Endpoint{
			Kind: model.EndpointService, Namespace: "default", Name: "backend",
		},
		Frontends: []model.Endpoint{{
			Kind: model.EndpointService, Namespace: "default", Name: "backend",
			Address: netip.MustParseAddr("10.0.130.86"), Port: 80,
		}},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "default", Name: "backend-abc",
			Node: "worker-b", Address: netip.MustParseAddr("10.0.2.8"), Port: 80,
		}},
		BackendCoverageKnown: true,
	}
	now := time.Now()
	events := []model.Observation{
		{Kind: model.KindTraceContext, Trace: &context},
		{Kind: model.KindStatus, Side: "source", AttachmentID: "source", Node: "worker-a", Interface: "veth-source"},
		{Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1", Node: "worker-b", Interface: "veth-backend"},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now,
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 53776, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
		},
		{
			Kind: model.KindPacket, Side: "backend", WallTime: now.Add(time.Millisecond),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			SrcPort: 53776, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
		},
		{
			Kind: model.KindPacket, Side: "backend", WallTime: now.Add(2 * time.Millisecond),
			Protocol: 6, SrcAddr: context.Backends[0].Address, DstAddr: context.Source.Address,
			SrcPort: 80, DstPort: 53776, TCPFlags: 0x12, TCPSequence: 500, TCPAck: 101,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(3 * time.Millisecond),
			Protocol: 6, SrcAddr: context.Frontends[0].Address, DstAddr: context.Source.Address,
			SrcPort: 80, DstPort: 53776, TCPFlags: 0x12, TCPSequence: 500, TCPAck: 101,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(4 * time.Millisecond),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 53776, DstPort: 80, TCPFlags: 0x18, TCPSequence: 101, TCPAck: 501,
		},
		{
			Kind: model.KindPacket, Side: "backend", WallTime: now.Add(5 * time.Millisecond),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			SrcPort: 53776, DstPort: 80, TCPFlags: 0x18, TCPSequence: 101, TCPAck: 501,
		},
		{
			Kind: model.KindPacket, Side: "backend", WallTime: now.Add(6 * time.Millisecond),
			Protocol: 6, SrcAddr: context.Backends[0].Address, DstAddr: context.Source.Address,
			SrcPort: 80, DstPort: 53776, TCPFlags: 0x18, TCPSequence: 501, TCPAck: 120,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(7 * time.Millisecond),
			Protocol: 6, SrcAddr: context.Frontends[0].Address, DstAddr: context.Source.Address,
			SrcPort: 80, DstPort: 53776, TCPFlags: 0x18, TCPSequence: 501, TCPAck: 120,
		},
	}
	var current tea.Model = m
	for _, event := range events {
		current, _ = current.Update(observationMsg{observation: event})
	}
	view := current.(Model).View()
	if !strings.Contains(view, "● to destination Pod") ||
		!strings.Contains(view, "Matching SYN observed through the destination Pod boundary.") ||
		!strings.Contains(view, "showing 1-8 of 8 observations") ||
		strings.Count(view, "PSH-ACK") != 4 {
		t.Fatalf("observed backend was not reflected in datapath view:\n%s", view)
	}
}

func TestDatapathVisualizationPrioritizesNewerBlockedDNS(t *testing.T) {
	observations := make(chan model.Observation)
	errorsChannel := make(chan error)
	m := New("trace", observations, errorsChannel)
	context := model.TraceContext{
		Mode: model.TraceModeService,
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "frontend",
			Node: "worker-a", Address: netip.MustParseAddr("10.244.0.5"),
		},
		Service: &model.Endpoint{Kind: model.EndpointService, Namespace: "demo", Name: "backend"},
		Frontends: []model.Endpoint{{
			Kind: model.EndpointService, Namespace: "demo", Name: "backend",
			Address: netip.MustParseAddr("10.96.0.20"), Port: 80,
		}},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "demo", Name: "backend-abc",
			Node: "worker-b", Address: netip.MustParseAddr("10.244.1.8"), Port: 80,
		}},
		DNSBackends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "kube-system", Name: "coredns-abc",
			Node: "worker-b", Address: netip.MustParseAddr("10.244.1.53"), Port: 53,
		}},
		DNSFrontends: []model.Endpoint{{
			Kind: model.EndpointService, Namespace: "kube-system", Name: "kube-dns",
			Address: netip.MustParseAddr("10.96.0.10"), Port: 53,
		}},
		NodeTransit: &model.NodeTransitContext{
			SourceNode: "worker-a", DestinationNodes: []string{"worker-b"},
		},
		Policies: []model.PolicyContext{{
			Namespace: "demo", Name: "deny-all-frontend", Scope: "source egress",
			Pods: []string{"frontend"}, DenyAll: true,
		}},
	}
	now := time.Now()
	dnsBackend := context.DNSBackends[0]
	events := []model.Observation{
		{Kind: model.KindTraceContext, Trace: &context},
		{Kind: model.KindStatus, Side: "source", AttachmentID: "source", Node: "worker-a", Interface: "veth-source"},
		{Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1", Node: "worker-b", Interface: "veth-backend"},
		{Kind: model.KindStatus, Side: "dns", AttachmentID: "dns-1", Node: "worker-b", Interface: "veth-dns"},
		{Kind: model.KindStatus, Side: "transit-source", AttachmentID: "transit-source-worker-b", Node: "worker-a", Interface: "eth0"},
		{Kind: model.KindStatus, Side: "transit-destination", AttachmentID: "transit-destination-worker-b", Node: "worker-b", Interface: "eth0"},
		{
			Kind: model.KindConnect, Side: "source", WallTime: now.Add(-time.Millisecond),
			DstAddr: context.Frontends[0].Address, DstPort: 80, CgroupID: 42,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now,
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
		},
		{
			Kind: model.KindTransit, Side: "transit-source", AttachmentID: "transit-source-worker-b",
			Node: "worker-a", WallTime: now.Add(time.Millisecond), Protocol: 6,
			SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
			Encapsulation: model.EncapsulationVXLAN, TunnelID: 16607,
		},
		{
			Kind: model.KindTransit, Side: "transit-destination", AttachmentID: "transit-destination-worker-b",
			Node: "worker-b", WallTime: now.Add(2 * time.Millisecond), Protocol: 6,
			SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
			Encapsulation: model.EncapsulationVXLAN, TunnelID: 16607,
		},
		{
			Kind: model.KindConnect, Side: "source", WallTime: now.Add(time.Minute - time.Millisecond),
			DstAddr: context.DNSFrontends[0].Address, DstPort: 53, CgroupID: 42,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Minute),
			Protocol: 17, SrcAddr: context.Source.Address, DstAddr: dnsBackend.Address,
			SrcPort: 53000, DstPort: 53, DstEndpoint: &dnsBackend,
		},
	}
	var current tea.Model = m
	for _, event := range events {
		current, _ = current.Update(observationMsg{observation: event})
	}
	view := current.(Model).View()
	for _, expected := range []string{
		"Latest focus: DNS prerequisite",
		"newer unresolved DNS query",
		"● source veth",
		"transit: [srcHostNetNS] ──×──",
		"gap is inside the source node",
		"Latest backend attempt · historical",
		"Newer unresolved DNS evidence supersedes this backend attempt",
		"NetworkPolicy demo/deny-all-frontend",
		"source egress deny-all",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("%q missing from view:\n%s", expected, view)
		}
	}
}

func TestServiceViewSeparatesCurrentAndPreviousAttempts(t *testing.T) {
	observations := make(chan model.Observation, 1)
	errors := make(chan error, 1)
	m := New("trace", observations, errors)
	context := model.TraceContext{
		Mode: model.TraceModeService,
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "frontend",
			Address: netip.MustParseAddr("10.244.0.5"),
		},
		Service: &model.Endpoint{Kind: model.EndpointService, Namespace: "demo", Name: "backend"},
		Frontends: []model.Endpoint{{
			Kind: model.EndpointService, Namespace: "demo", Name: "backend",
			Address: netip.MustParseAddr("10.96.0.20"), Port: 80,
		}},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "demo", Name: "backend-abc",
			Address: netip.MustParseAddr("10.244.1.8"), Port: 80,
		}},
	}
	now := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	events := []model.Observation{
		{Kind: model.KindTraceContext, Trace: &context},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now,
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
		},
		{
			Kind: model.KindPacket, Side: "backend", WallTime: now.Add(time.Millisecond),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
		},
		{
			Kind: model.KindPacket, Side: "backend", WallTime: now.Add(2 * time.Millisecond),
			Protocol: 6, SrcAddr: context.Backends[0].Address, DstAddr: context.Source.Address,
			SrcPort: 80, DstPort: 40000, TCPFlags: 0x12, TCPAck: 101,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Minute),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 40001, DstPort: 80, TCPFlags: 0x02, TCPSequence: 200,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Minute + time.Second),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 40001, DstPort: 80, TCPFlags: 0x02, TCPSequence: 200,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(2 * time.Minute),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
		},
	}
	var current tea.Model = m
	for _, event := range events {
		current, _ = current.Update(observationMsg{observation: event})
	}
	current, _ = current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	view := current.(Model).View()
	for _, expected := range []string{
		"Attempts 2",
		"Current attempt",
		"08:01:00.000000",
		"client :40001",
		"2 SYNs; no backend SYN or response observed",
		"Previous attempts",
		"08:00:00.000000",
		"client :40000",
		"backend SYN and response observed",
		"Current attempt observations",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("%q missing from attempt view:\n%s", expected, view)
		}
	}
	if strings.Contains(view, "\nFlows\n") || strings.Contains(view, "both directions observed") {
		t.Fatalf("generic historical flow state leaked into Service view:\n%s", view)
	}
	if current.(Model).activeTraceFlow != "6/10.244.0.5/40001/200" {
		t.Fatalf("active trace flow = %q", current.(Model).activeTraceFlow)
	}
}

func TestViewShowsPodPathScope(t *testing.T) {
	observations := make(chan model.Observation, 1)
	errors := make(chan error, 1)
	m := New("trace", observations, errors)
	source := model.Endpoint{
		Kind: model.EndpointPod, Namespace: "demo", Name: "frontend",
		Address: netip.MustParseAddr("10.0.0.1"),
	}
	destination := model.Endpoint{
		Kind: model.EndpointPod, Namespace: "demo", Name: "backend",
		Address: netip.MustParseAddr("10.0.0.2"),
	}
	context := model.TraceContext{
		Mode: model.TraceModePod, Source: source, Destination: &destination,
	}
	events := []model.Observation{
		{Kind: model.KindTraceContext, Trace: &context},
		{
			Kind: model.KindPacket, Side: "source", Protocol: 6,
			SrcAddr: source.Address, DstAddr: destination.Address,
			SrcPort: 40000, DstPort: 80, SrcEndpoint: &source, DstEndpoint: &destination,
		},
		{
			Kind: model.KindPacket, Side: "destination", Protocol: 6,
			SrcAddr: source.Address, DstAddr: destination.Address,
			SrcPort: 40000, DstPort: 80, SrcEndpoint: &source, DstEndpoint: &destination,
		},
	}
	var current tea.Model = m
	for _, event := range events {
		current, _ = current.Update(observationMsg{observation: event})
	}
	current, _ = current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	view := current.(Model).View()
	if !strings.Contains(view, "Pod path") ||
		!strings.Contains(view, "frontend.demo") ||
		!strings.Contains(view, "backend.demo") ||
		!strings.Contains(view, "traffic observed at both selected Pod boundaries") {
		t.Fatalf("unexpected Pod path view:\n%s", view)
	}
}

func TestViewShowsSeparateDNSExchange(t *testing.T) {
	observations := make(chan model.Observation, 1)
	errors := make(chan error, 1)
	m := New("trace", observations, errors)
	source := model.Endpoint{
		Kind: model.EndpointPod, Namespace: "demo", Name: "frontend",
		Address: netip.MustParseAddr("10.244.0.5"),
	}
	context := model.TraceContext{
		Source: source,
		Service: &model.Endpoint{
			Kind: model.EndpointService, Namespace: "demo", Name: "backend",
		},
		Frontends: []model.Endpoint{{
			Kind: model.EndpointService, Namespace: "demo", Name: "backend",
			Address: netip.MustParseAddr("10.96.0.20"), Port: 80,
		}},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "demo", Name: "backend-abc",
			Address: netip.MustParseAddr("10.244.1.8"), Port: 80,
		}},
	}
	kubeDNS := model.Endpoint{
		Kind: model.EndpointService, Namespace: "kube-system", Name: "kube-dns",
		Address: netip.MustParseAddr("10.96.0.10"), Port: 53,
	}
	coreDNS := model.Endpoint{
		Kind: model.EndpointPod, Namespace: "kube-system", Name: "coredns-abc",
		Address: netip.MustParseAddr("10.244.0.4"), Port: 53,
	}
	context.DNSService = &kubeDNS
	context.DNSFrontends = []model.Endpoint{kubeDNS}
	context.DNSBackends = []model.Endpoint{coreDNS}
	now := time.Now()
	events := []model.Observation{
		{Kind: model.KindTraceContext, Trace: &context},
		{
			Kind: model.KindConnect, Side: "source", WallTime: now,
			DstAddr: kubeDNS.Address, DstPort: 53, DstEndpoint: &kubeDNS,
			Confidence: model.ConfidenceExact,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Microsecond),
			Node: "worker-a", Protocol: 17, SrcAddr: source.Address, DstAddr: kubeDNS.Address,
			SrcPort: 40000, DstPort: 53, SrcEndpoint: &source, DstEndpoint: &kubeDNS,
			Confidence: model.ConfidenceExact,
		},
		{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(2 * time.Microsecond),
			Node: "worker-a", Protocol: 17, SrcAddr: kubeDNS.Address, DstAddr: source.Address,
			SrcPort: 53, DstPort: 40000, SrcEndpoint: &kubeDNS, DstEndpoint: &source,
			Confidence: model.ConfidenceExact,
		},
		{
			Kind: model.KindPacket, Side: "dns", WallTime: now.Add(1500 * time.Nanosecond),
			Node: "worker-b", Protocol: 17, SrcAddr: source.Address, DstAddr: coreDNS.Address,
			SrcPort: 40000, DstPort: 53, SrcEndpoint: &source, DstEndpoint: &coreDNS,
			Confidence: model.ConfidenceExact,
		},
		{
			Kind: model.KindPacket, Side: "dns", WallTime: now.Add(1600 * time.Nanosecond),
			Node: "worker-b", Protocol: 17, SrcAddr: coreDNS.Address, DstAddr: source.Address,
			SrcPort: 53, DstPort: 40000, SrcEndpoint: &coreDNS, DstEndpoint: &source,
			Confidence: model.ConfidenceExact,
		},
	}
	var current tea.Model = m
	for _, event := range events {
		current, _ = current.Update(observationMsg{observation: event})
	}
	view := current.(Model).View()
	for _, expected := range []string{
		"DNS exchange",
		"kube-dns.kube-system",
		"coredns-abc.kube-system",
		"CoreDNS responder",
		"CoreDNS boundary",
		"queries=1 responses=1",
		"DNS Service translation occurred between the source Pod and CoreDNS boundaries",
		"node-local chronology",
		"UDP",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("%q missing from DNS view:\n%s", expected, view)
		}
	}
}

func TestWaitForStreamReportsErrorsImmediately(t *testing.T) {
	observations := make(chan model.Observation)
	errorsChannel := make(chan error, 1)
	errorsChannel <- errors.New("source attachment failed")
	message := waitForStream(observations, errorsChannel)()
	streamError, ok := message.(streamErrorMsg)
	if !ok || !strings.Contains(streamError.err.Error(), "source attachment failed") {
		t.Fatalf("message = %#v", message)
	}
}

func TestCurrentFlowRetainsAndSortsAllPackets(t *testing.T) {
	observations := make(chan model.Observation)
	errorsChannel := make(chan error)
	m := New("flow", observations, errorsChannel)
	m.height = 100
	base := time.Now()
	for i := 14; i >= 0; i-- {
		updated, _ := m.Update(observationMsg{observation: model.Observation{
			SchemaVersion: model.SchemaVersion,
			Kind:          model.KindPacket,
			Node:          "worker-a",
			Point:         "host-veth/tcx",
			Direction:     model.DirectionIngress,
			MonotonicNS:   uint64(1000 + i),
			WallTime:      base.Add(time.Duration(i) * time.Microsecond),
			Protocol:      6,
			SrcAddr:       netip.MustParseAddr("10.0.0.1"),
			DstAddr:       netip.MustParseAddr("10.0.0.2"),
			SrcPort:       1234,
			DstPort:       80,
			PacketLength:  uint32(60 + i),
			TCPFlags:      0x10,
			Confidence:    model.ConfidenceExact,
		}})
		m = updated.(Model)
	}
	rows, packetCount, multipleNodes := m.packetRows()
	if packetCount != 15 || len(rows) != 15 || multipleNodes {
		t.Fatalf("rows=%d packets=%d multipleNodes=%v", len(rows), packetCount, multipleNodes)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].observation.MonotonicNS >= rows[i].observation.MonotonicNS {
			t.Fatalf("packets are not chronological: %d then %d",
				rows[i-1].observation.MonotonicNS, rows[i].observation.MonotonicNS)
		}
	}
	view := m.View()
	if !strings.Contains(view, "showing 1-15 of 15 observations") {
		t.Fatalf("full flow history missing:\n%s", view)
	}
}

func TestPacketTimelineScrollsWithoutDiscardingHistory(t *testing.T) {
	observations := make(chan model.Observation)
	errorsChannel := make(chan error)
	m := New("flow", observations, errorsChannel)
	m.height = 12
	base := time.Now()
	for i := 0; i < 15; i++ {
		updated, _ := m.Update(observationMsg{observation: model.Observation{
			Kind: model.KindPacket, Node: "worker-a", Point: "host-veth/tcx",
			Direction: model.DirectionIngress, MonotonicNS: uint64(i + 1),
			WallTime: base.Add(time.Duration(i) * time.Microsecond),
			Protocol: 6, SrcAddr: netip.MustParseAddr("10.0.0.1"),
			DstAddr: netip.MustParseAddr("10.0.0.2"), SrcPort: 1234, DstPort: 80,
			PacketLength: uint32(60 + i), TCPFlags: 0x10, Confidence: model.ConfidenceExact,
		}})
		m = updated.(Model)
	}
	if strings.Contains(m.View(), "74B") {
		t.Fatal("last packet should be below the initial viewport")
	}
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	m = updated.(Model)
	if !strings.Contains(m.View(), "74B") || m.viewOffset == 0 {
		t.Fatalf("last packet was not reachable after scrolling:\n%s", m.View())
	}
}

func TestCrossNodePacketsUseSeparateChronologies(t *testing.T) {
	observations := make(chan model.Observation)
	errorsChannel := make(chan error)
	m := New("flow", observations, errorsChannel)
	destination := model.Endpoint{
		Kind: model.EndpointPod, Namespace: "demo", Name: "server", Address: netip.MustParseAddr("10.0.0.2"),
	}

	context := model.TraceContext{
		Mode:        model.TraceModePod,
		Source:      model.Endpoint{Kind: model.EndpointPod, Namespace: "demo", Name: "client", Address: netip.MustParseAddr("10.0.0.1")},
		Destination: &destination,
	}

	updated, _ := m.Update(observationMsg{observation: model.Observation{Kind: model.KindTraceContext, Trace: &context}})
	m = updated.(Model)
	for _, event := range []model.Observation{
		{Kind: model.KindPacket, Node: "worker-b", MonotonicNS: 1, WallTime: time.Now(), Protocol: 6, SrcAddr: context.Source.Address, DstAddr: netip.MustParseAddr("10.0.0.2"), SrcPort: 1234, DstPort: 80},
		{Kind: model.KindPacket, Node: "worker-a", MonotonicNS: 2, WallTime: time.Now(), Protocol: 6, SrcAddr: context.Source.Address, DstAddr: netip.MustParseAddr("10.0.0.2"), SrcPort: 1234, DstPort: 80},
	} {
		updated, _ = m.Update(observationMsg{observation: event})
		m = updated.(Model)
	}
	view := m.View()
	if !strings.Contains(view, "node-local chronology") ||
		!strings.Contains(view, "node worker-a") ||
		!strings.Contains(view, "node worker-b") ||
		!strings.Contains(view, "showing 1-2 of 2 observations") {
		t.Fatalf("cross-node separation missing:\n%s", view)
	}
}

func TestViewShowsVXLANNodeTransitSeparately(t *testing.T) {
	observations := make(chan model.Observation)
	errorsChannel := make(chan error)
	m := New("trace", observations, errorsChannel)
	destination := model.Endpoint{
		Kind: model.EndpointPod, Namespace: "demo", Name: "server", Address: netip.MustParseAddr("10.244.1.8"),
	}
	context := model.TraceContext{
		Mode: model.TraceModePod,
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "client", Address: netip.MustParseAddr("10.244.0.5"),
		},
		Destination: &destination,
		NodeTransit: &model.NodeTransitContext{
			SourceNode: "worker-a", DestinationNodes: []string{"worker-b"},
		},
	}
	events := []model.Observation{
		{Kind: model.KindTraceContext, Trace: &context},
		{Kind: model.KindStatus, Side: "source", AttachmentID: "source", Node: "worker-a", Interface: "veth-source"},
		{Kind: model.KindStatus, Side: "destination", AttachmentID: "destination", Node: "worker-b", Interface: "veth-destination"},
		{Kind: model.KindStatus, Side: "transit-source", AttachmentID: "transit-source-worker-b", Node: "worker-a", Interface: "eth0"},
		{Kind: model.KindStatus, Side: "transit-destination", AttachmentID: "transit-destination-worker-b", Node: "worker-b", Interface: "eth0"},
	}

	for index, node := range []string{"worker-a", "worker-b"} {
		events = append(events, model.Observation{
			Kind: model.KindTransit, Side: []string{"transit-source", "transit-destination"}[index],
			AttachmentID: []string{"transit-source-worker-b", "transit-destination-worker-b"}[index],
			Node:         node, Interface: "eth0", Direction: model.DirectionEgress,
			MonotonicNS: uint64(index + 1), WallTime: time.Now(), Protocol: 6,
			SrcAddr: context.Source.Address, DstAddr: destination.Address, SrcPort: 40000, DstPort: 80,
			Encapsulation: model.EncapsulationVXLAN, TunnelID: 1,
			OuterSrcAddr: netip.MustParseAddr("172.18.0.2"), OuterDstAddr: netip.MustParseAddr("172.18.0.3"),
			OuterSrcPort: 40001, OuterDstPort: 8472,
		})
	}
	var current tea.Model = m
	for _, event := range events {
		current, _ = current.Update(observationMsg{observation: event})
	}
	current, _ = current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	view := current.(Model).View()
	for _, expected := range []string{
		"Datapath evidence",
		"srcNode: worker-a",
		"[srcPodNetNS: client.demo]",
		"source veth",
		"transit: [srcHostNetNS]",
		"VXLAN vni=1",
		"[dstHostNetNS]",
		"to destination Pod",
		"[dstPodNetNS: server.demo]",
		"● observed",
		"Node transit", "worker-a/eth0", "worker-b/eth0",
		"source node worker-a · monotonic order",
		"destination node worker-b · monotonic order",
		"inner 10.244.0.5:40000 → 10.244.1.8:80",
		"node clocks are not compared",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("%q missing from transit view:\n%s", expected, view)
		}
	}
	if strings.Contains(view[strings.Index(view, "Current flow observations"):], "VXLAN vni=1") {
		t.Fatalf("transit evidence leaked into Pod packet timeline:\n%s", view)
	}

	current, _ = current.Update(tea.WindowSizeMsg{Width: 100, Height: 10})
	current, _ = current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	if strings.Contains(current.(Model).View(), "Trace evidence") {
		t.Fatalf("end of viewport unexpectedly includes top evidence:\n%s", current.(Model).View())
	}
	current, _ = current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	top := current.(Model).View()
	if !strings.Contains(top, "Datapath evidence") || !strings.Contains(top, "lines 1-9 of") {
		t.Fatalf("top of the whole view is not reachable:\n%s", top)
	}
	foundTraceEvidence := false
	foundNodeTransit := false
	for range 5 {
		current, _ = current.Update(tea.KeyMsg{Type: tea.KeyPgDown})
		page := current.(Model).View()
		foundTraceEvidence = foundTraceEvidence || strings.Contains(page, "Trace evidence")
		foundNodeTransit = foundNodeTransit || strings.Contains(page, "Node transit")
	}
	if !foundTraceEvidence {
		t.Fatalf("Trace evidence is not reachable by scrolling the whole view:\n%s", current.(Model).View())
	}
	if !foundNodeTransit {
		t.Fatalf("Node transit is not reachable by scrolling the whole view:\n%s", current.(Model).View())
	}
}

func TestStatusCountsAllEvidenceAndAttachmentLoss(t *testing.T) {
	observations := make(chan model.Observation)
	errorsChannel := make(chan error)
	m := New("counts", observations, errorsChannel)
	events := []model.Observation{
		{
			Kind: model.KindPacket, AttachmentID: "source", Lost: 2,
			Protocol: 6, SrcAddr: netip.MustParseAddr("10.0.0.1"), DstAddr: netip.MustParseAddr("10.0.0.2"),
		},
		{
			Kind: model.KindTransit, AttachmentID: "transit", Lost: 3,
			Protocol: 6, SrcAddr: netip.MustParseAddr("10.0.0.1"), DstAddr: netip.MustParseAddr("10.0.0.2"),
		},
		{
			Kind: model.KindConnect, AttachmentID: "connect", Lost: 1,
			DstAddr: netip.MustParseAddr("10.0.0.2"),
		},
	}
	for _, event := range events {
		updated, _ := m.Update(observationMsg{observation: event})
		m = updated.(Model)
	}
	view := m.View()
	if !strings.Contains(view, "Boundary 1  Transit 1  Connect 1  Lost 6") {
		t.Fatalf("evidence counters are inaccurate:\n%s", view)
	}
}
