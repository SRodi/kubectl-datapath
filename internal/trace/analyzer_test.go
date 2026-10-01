package trace

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestAnalyzerLocatesTranslationAfterSourceBoundary(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", WallTime: now,
		DstAddr: context.Frontends[0].Address, DstPort: 80,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
		SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "backend", WallTime: now.Add(2 * time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: 8080, TCPFlags: 0x02, TCPSequence: 100,
	})
	if got := analyzer.Conclusion(); !strings.Contains(got, "translation occurred between them") {
		t.Fatalf("conclusion = %q", got)
	}
}

func TestRelevantIncludesSourceDNSPackets(t *testing.T) {
	context := testContext()
	query := model.Observation{
		Kind: model.KindPacket, Side: "source", Protocol: 17,
		SrcAddr: context.Source.Address, DstAddr: netip.MustParseAddr("10.96.0.10"),
		SrcPort: 53000, DstPort: 53,
	}
	if !Relevant(query, context) {
		t.Fatal("DNS query was rejected")
	}
	response := query
	response.SrcAddr, response.DstAddr = query.DstAddr, query.SrcAddr
	response.SrcPort, response.DstPort = 53, 53000
	if !Relevant(response, context) {
		t.Fatal("DNS response was rejected")
	}
	backendQuery := query
	backendQuery.Side = "dns"
	backendQuery.DstAddr = context.DNSBackends[0].Address
	if !Relevant(backendQuery, context) {
		t.Fatal("DNS backend query was rejected")
	}
}

func TestRelevantExcludesUnrelatedPodTraffic(t *testing.T) {
	context := testContext()
	unrelated := model.Observation{
		Kind: model.KindPacket, Side: "source",
		SrcAddr: context.Source.Address,
		DstAddr: netip.MustParseAddr("fd00:10::99"),
	}
	if Relevant(unrelated, context) {
		t.Fatal("unrelated packet was accepted")
	}
	servicePacket := unrelated
	servicePacket.DstAddr = context.Frontends[0].Address
	if !Relevant(servicePacket, context) {
		t.Fatal("Service packet was rejected")
	}
}

func TestRelevantPodPathIncludesOnlySelectedPair(t *testing.T) {
	context := testContext()
	destination := context.Backends[0]
	context.Mode = model.TraceModePod
	context.Destination = &destination
	pair := model.Observation{
		Kind: model.KindPacket, Side: "source", Protocol: 6,
		SrcAddr: context.Source.Address, DstAddr: destination.Address,
		SrcPort: 40000, DstPort: 8080,
	}

	if !RelevantPodPath(pair, context) {
		t.Fatal("selected Pod pair traffic was rejected")
	}

	reverse := pair
	reverse.SrcAddr, reverse.DstAddr = pair.DstAddr, pair.SrcAddr
	reverse.SrcPort, reverse.DstPort = pair.DstPort, pair.SrcPort
	if !RelevantPodPath(reverse, context) {
		t.Fatal("reverse Pod pair traffic was rejected")
	}
	unrelated := pair
	unrelated.DstAddr = netip.MustParseAddr("fd00:10::99")
	if RelevantPodPath(unrelated, context) {
		t.Fatal("unrelated traffic was accepted")
	}
}

func TestAnalyzerReportsVXLANTransitForCurrentAttempt(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	context.Mode = model.TraceModeService
	context.NodeTransit = &model.NodeTransitContext{
		SourceNode: "worker-a", DestinationNodes: []string{"worker-b"},
	}

	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	for _, status := range []model.Observation{
		{Kind: model.KindStatus, Side: "source", AttachmentID: "source", Node: "worker-a", Interface: "veth-source"},
		{Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1", Node: "worker-b", Interface: "veth-backend"},
		{Kind: model.KindStatus, Side: "transit-source", AttachmentID: "transit-source-worker-b", Node: "worker-a", Interface: "eth0"},
		{Kind: model.KindStatus, Side: "transit-destination", AttachmentID: "transit-destination-worker-b", Node: "worker-b", Interface: "eth0"},
	} {
		analyzer.Observe(status)
	}
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now,
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
		SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
	})
	for index, node := range []string{"worker-a", "worker-b"} {
		analyzer.Observe(model.Observation{
			Kind: model.KindTransit, Side: []string{"transit-source", "transit-destination"}[index],
			AttachmentID: []string{"transit-source-worker-b", "transit-destination-worker-b"}[index],
			Node:         node, Interface: "eth0", WallTime: now.Add(time.Millisecond),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			SrcPort: 40000, DstPort: context.Backends[0].Port, TCPFlags: 0x02, TCPSequence: 100,
			Encapsulation: model.EncapsulationVXLAN, TunnelID: 1,
		})
	}
	transit := analyzer.Transit()
	if transit == nil || len(transit.Observations) != 2 {
		t.Fatalf("transit = %#v", transit)
	}
	if !strings.Contains(transit.Conclusion, "VXLAN transit observed on both") {
		t.Fatalf("conclusion = %q", transit.Conclusion)
	}
	datapath := analyzer.Datapath()
	if datapath == nil || !datapath.CrossNode ||
		datapath.SourceTransit == nil || datapath.SourceTransit.State != "OBSERVED" ||
		datapath.DestinationTransit == nil || datapath.DestinationTransit.State != "OBSERVED" ||
		datapath.TransitLabel != "VXLAN vni=1" {
		t.Fatalf("datapath = %#v", datapath)
	}
	if !strings.Contains(datapath.Diagnosis, "inside the destination node") {
		t.Fatalf("diagnosis = %q", datapath.Diagnosis)
	}
}

func TestAnalyzerUsesNewerUnresolvedDNSAsDatapathFocus(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	context.Mode = model.TraceModeService
	context.Source.Node = "worker-a"
	context.Backends[0].Node = "worker-b"
	context.DNSBackends[0].Node = "worker-b"
	context.NodeTransit = &model.NodeTransitContext{
		SourceNode: "worker-a", DestinationNodes: []string{"worker-b"},
	}
	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	for _, status := range []model.Observation{
		{Kind: model.KindStatus, Side: "source", AttachmentID: "source", Node: "worker-a", Interface: "veth-source"},
		{Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1", Node: "worker-b", Interface: "veth-backend"},
		{Kind: model.KindStatus, Side: "dns", AttachmentID: "dns-1", Node: "worker-b", Interface: "veth-dns"},
		{Kind: model.KindStatus, Side: "transit-source", AttachmentID: "transit-source-worker-b", Node: "worker-a", Interface: "eth0"},
		{Kind: model.KindStatus, Side: "transit-destination", AttachmentID: "transit-destination-worker-b", Node: "worker-b", Interface: "eth0"},
	} {
		analyzer.Observe(status)
	}
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", WallTime: now.Add(-time.Millisecond),
		DstAddr: context.Frontends[0].Address, DstPort: context.Frontends[0].Port, CgroupID: 42,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now,
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: context.Backends[0].Port, TCPFlags: 0x02, TCPSequence: 100,
	})
	for index, node := range []string{"worker-a", "worker-b"} {
		analyzer.Observe(model.Observation{
			Kind: model.KindTransit, Side: []string{"transit-source", "transit-destination"}[index],
			AttachmentID: []string{"transit-source-worker-b", "transit-destination-worker-b"}[index],
			Node:         node, WallTime: now.Add(time.Millisecond), Protocol: 6,
			SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
			SrcPort: 40000, DstPort: context.Backends[0].Port,
			TCPFlags: 0x02, TCPSequence: 100, Encapsulation: model.EncapsulationVXLAN,
		})
	}
	dnsBackend := context.DNSBackends[0]
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", WallTime: now.Add(time.Minute - time.Millisecond),
		DstAddr: context.DNSFrontends[0].Address, DstPort: 53, CgroupID: 42,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Minute),
		Protocol: 17, SrcAddr: context.Source.Address, DstAddr: dnsBackend.Address,
		SrcPort: 53000, DstPort: 53, DstEndpoint: &dnsBackend,
	})

	datapath := analyzer.Datapath()
	if datapath == nil || datapath.Focus != "DNS prerequisite" || !datapath.AttemptSuperseded {
		t.Fatalf("datapath focus = %#v", datapath)
	}
	if datapath.Destination.Name != dnsBackend.Name ||
		datapath.SourceBoundary.State != "OBSERVED" ||
		datapath.SourceTransit == nil || datapath.SourceTransit.State != "NO EVIDENCE" ||
		datapath.DestinationTransit == nil || datapath.DestinationTransit.State != "NO EVIDENCE" {
		t.Fatalf("DNS datapath = %#v", datapath)
	}
	if !strings.Contains(datapath.Diagnosis, "inside the source node") {
		t.Fatalf("diagnosis = %q", datapath.Diagnosis)
	}
	if transit := analyzer.Transit(); transit == nil || len(transit.Observations) != 0 {
		t.Fatalf("DNS transit = %#v", transit)
	}
}

func TestAnalyzerDoesNotPromoteDNSFromDifferentCgroup(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", WallTime: now,
		DstAddr: context.Frontends[0].Address, DstPort: context.Frontends[0].Port, CgroupID: 42,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: context.Backends[0].Port, TCPFlags: 0x02, TCPSequence: 100,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", WallTime: now.Add(time.Minute),
		DstAddr: context.DNSFrontends[0].Address, DstPort: 53, CgroupID: 99,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Minute + time.Millisecond),
		Protocol: 17, SrcAddr: context.Source.Address, DstAddr: context.DNSBackends[0].Address,
		SrcPort: 53000, DstPort: 53,
	})
	if datapath := analyzer.Datapath(); datapath == nil || datapath.Focus != "backend TCP attempt" {
		t.Fatalf("datapath = %#v", datapath)
	}
}

func TestAnalyzerRejectsTransitFromDifferentTCPSequence(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	context.Mode = model.TraceModeService
	context.Source.Node = "worker-a"
	context.Backends[0].Node = "worker-b"
	context.NodeTransit = &model.NodeTransitContext{
		SourceNode: "worker-a", DestinationNodes: []string{"worker-b"},
	}
	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now,
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: context.Backends[0].Port, TCPFlags: 0x02, TCPSequence: 200,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindTransit, Side: "transit-source", AttachmentID: "transit-source-worker-b",
		Node: "worker-a", WallTime: now.Add(time.Millisecond), Protocol: 6,
		SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: context.Backends[0].Port,
		TCPFlags: 0x02, TCPSequence: 100, Encapsulation: model.EncapsulationVXLAN,
	})
	if transit := analyzer.Transit(); transit == nil || len(transit.Observations) != 0 {
		t.Fatalf("stale transit matched current attempt: %#v", transit)
	}
}

func TestAnalyzerDescribesDNSFocusBeforeAnyBackendAttempt(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	context.Mode = model.TraceModeService
	context.Source.Node = "worker-a"
	context.DNSBackends[0].Node = "worker-b"
	context.NodeTransit = &model.NodeTransitContext{
		SourceNode: "worker-a", DestinationNodes: []string{"worker-b"},
	}
	now := time.Now()
	dnsService := *context.DNSService
	dnsBackend := context.DNSBackends[0]
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", WallTime: now,
		DstAddr: dnsService.Address, DstPort: 53, DstEndpoint: &dnsService,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Millisecond),
		Protocol: 17, SrcAddr: context.Source.Address, DstAddr: dnsBackend.Address,
		SrcPort: 53000, DstPort: 53, DstEndpoint: &dnsBackend,
	})

	datapath := analyzer.Datapath()
	if datapath == nil || datapath.AttemptSuperseded ||
		!strings.Contains(datapath.FocusDetail, "backend TCP connect has not started") {
		t.Fatalf("datapath focus = %#v", datapath)
	}
	if datapath.ConnectLabel != dnsService.DisplayName() {
		t.Fatalf("connect label = %q", datapath.ConnectLabel)
	}
}

func TestAnalyzerLocatesTranslationBeforeSourceBoundary(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", WallTime: now,
		DstAddr: context.Frontends[0].Address, DstPort: 80,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: 8080, TCPFlags: 0x02, TCPSequence: 100,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "backend", WallTime: now.Add(2 * time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: 8080, TCPFlags: 0x02, TCPSequence: 100,
	})
	if got := analyzer.Conclusion(); !strings.Contains(got, "before the source Pod boundary") {
		t.Fatalf("conclusion = %q", got)
	}
}

func TestAnalyzerMarksBackendOnlyTraceIncomplete(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindStatus, Side: "source", AttachmentID: "source",
		Interface: "veth-source", InterfaceIdx: 12, Hooks: []string{"tcx/ingress", "fentry/__sys_connect"},
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1",
		Interface: "veth-backend", InterfaceIdx: 13, Hooks: []string{"tcx/ingress", "tcx/egress"},
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: time.Now(),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 1234, DstPort: context.Backends[0].Port, TCPFlags: 0x02, TCPSequence: 100,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "backend", WallTime: time.Now(),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 9999, DstPort: context.Backends[0].Port, TCPFlags: 0x02, TCPSequence: 200,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: time.Now().Add(time.Second),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 1234, DstPort: context.Backends[0].Port, TCPFlags: 0x02, TCPSequence: 100,
	})
	if got := analyzer.Conclusion(); !strings.Contains(got, "2 source SYNs, no matching backend SYN") {
		t.Fatalf("conclusion = %q", got)
	}
	health := analyzer.Health()
	if health[1].State != "OBSERVED" || health[2].State != "NO EVIDENCE" {
		t.Fatalf("health = %#v", health)
	}
}

func TestAnalyzerCorrelatesBackendArrivingBeforeSource(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", WallTime: now,
		DstAddr: context.Frontends[0].Address, DstPort: 80,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "backend", WallTime: now.Add(2 * time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: 8080, TCPFlags: 0x02, TCPSequence: 100,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: 8080, TCPFlags: 0x02, TCPSequence: 100,
	})
	if analyzer.Health()[2].State != "OBSERVED" {
		t.Fatalf("health = %#v", analyzer.Health())
	}
}

func TestAnalyzerDoesNotInterpretGapWhenEventsWereLost(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1",
		Interface: "veth-backend", Lost: 1,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: time.Now(),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 1234, DstPort: 8080, TCPFlags: 0x02, TCPSequence: 100,
	})
	if got := analyzer.Conclusion(); !strings.Contains(got, "event loss prevents interpreting") {
		t.Fatalf("conclusion = %q", got)
	}
	if got := analyzer.Health()[2].State; got != "INCOMPLETE" {
		t.Fatalf("backend health = %q", got)
	}
}

func TestAnalyzerDoesNotInterpretGapWhenTransportEventsWereLost(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1",
		Interface: "veth-backend", TransportLost: 1,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: time.Now(),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 1234, DstPort: 8080, TCPFlags: 0x02, TCPSequence: 100,
	})
	if got := analyzer.Conclusion(); !strings.Contains(got, "event loss prevents interpreting") {
		t.Fatalf("conclusion = %q", got)
	}
	health := analyzer.Health()[2]
	if health.State != "INCOMPLETE" || !strings.Contains(health.Detail, "transport loss=1") {
		t.Fatalf("backend health = %#v", health)
	}
}

func TestAnalyzerSeparatesCurrentAndPreviousAttempts(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})

	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now,
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
		SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "backend", WallTime: now.Add(time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: 8080, TCPFlags: 0x02, TCPSequence: 100,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "backend", WallTime: now.Add(2 * time.Millisecond),
		Protocol: 6, SrcAddr: context.Backends[0].Address, DstAddr: context.Source.Address,
		SrcPort: 8080, DstPort: 40000, TCPFlags: 0x12, TCPAck: 101,
	})

	for _, observedAt := range []time.Time{now.Add(time.Minute), now.Add(time.Minute + time.Second)} {
		analyzer.Observe(model.Observation{
			Kind: model.KindPacket, Side: "source", WallTime: observedAt,
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 40001, DstPort: 80, TCPFlags: 0x02, TCPSequence: 200,
		})
	}

	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now.Add(2 * time.Minute),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
		SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: 100,
	})

	attempts := analyzer.Attempts()
	if len(attempts) != 2 {
		t.Fatalf("attempts = %#v", attempts)
	}
	if !attempts[0].Active || attempts[0].SourcePort != 40001 || attempts[0].SYNs != 2 ||
		attempts[0].BackendObserved || attempts[0].ResponseObserved ||
		!strings.Contains(attempts[0].Status, "no backend SYN or response") {
		t.Fatalf("current attempt = %#v", attempts[0])
	}
	if attempts[1].Active || attempts[1].SourcePort != 40000 ||
		!attempts[1].BackendObserved || !attempts[1].ResponseObserved ||
		attempts[1].Status != "backend SYN and response observed" {
		t.Fatalf("previous attempt = %#v", attempts[1])
	}
}

func TestAnalyzerMatchesResponsesByInitialSequence(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	now := time.Now()
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	for _, sequence := range []uint32{100, 200} {
		analyzer.Observe(model.Observation{
			Kind: model.KindPacket, Side: "source", WallTime: now.Add(time.Duration(sequence) * time.Millisecond),
			Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
			SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, TCPSequence: sequence,
		})
	}
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "backend", WallTime: now.Add(time.Second),
		Protocol: 6, SrcAddr: context.Backends[0].Address, DstAddr: context.Source.Address,
		SrcPort: 8080, DstPort: 40000, TCPFlags: 0x12, TCPAck: 101,
	})

	attempts := analyzer.Attempts()
	if len(attempts) != 2 || attempts[0].InitialSequence != 200 || attempts[0].ResponseObserved ||
		attempts[1].InitialSequence != 100 || !attempts[1].ResponseObserved {
		t.Fatalf("attempts = %#v", attempts)
	}
}

func TestAnalyzerShowsDNSDestinationChange(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	dnsService := model.Endpoint{
		Kind: model.EndpointService, Namespace: "kube-system", Name: "kube-dns",
		Address: netip.MustParseAddr("10.96.0.10"), Port: 53,
	}
	coreDNS := model.Endpoint{
		Kind: model.EndpointPod, Namespace: "kube-system", Name: "coredns-abc",
		Address: netip.MustParseAddr("10.244.0.4"), Port: 53,
	}
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source", DstAddr: dnsService.Address, DstPort: 53,
		DstEndpoint: &dnsService,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", Protocol: 17,
		SrcAddr: context.Source.Address, DstAddr: coreDNS.Address, SrcPort: 53000, DstPort: 53,
		DstEndpoint: &coreDNS,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", Protocol: 17,
		SrcAddr: coreDNS.Address, DstAddr: context.Source.Address, SrcPort: 53, DstPort: 53000,
	})
	dns := analyzer.DNS()
	if dns == nil || dns.Queries != 1 || dns.Responses != 1 ||
		!strings.Contains(dns.Conclusion, "changed before") ||
		dns.Observed == nil || dns.Observed.Name != "coredns-abc" {
		t.Fatalf("DNS activity = %#v", dns)
	}
}

func TestAnalyzerIdentifiesCoreDNSResponderAfterLaterTranslation(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	dnsService := *context.DNSService
	coreDNS := context.DNSBackends[0]
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindConnect, Side: "source",
		DstAddr: dnsService.Address, DstPort: 53, DstEndpoint: &dnsService,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", Protocol: 17,
		SrcAddr: context.Source.Address, DstAddr: dnsService.Address,
		SrcPort: 53000, DstPort: 53, DstEndpoint: &dnsService,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "dns", Protocol: 17,
		SrcAddr: context.Source.Address, DstAddr: coreDNS.Address,
		SrcPort: 53000, DstPort: 53, DstEndpoint: &coreDNS,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "dns", Protocol: 17,
		SrcAddr: coreDNS.Address, DstAddr: context.Source.Address,
		SrcPort: 53, DstPort: 53000, SrcEndpoint: &coreDNS,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "dns", Protocol: 17,
		SrcAddr: context.Source.Address, DstAddr: coreDNS.Address,
		SrcPort: 54000, DstPort: 53, DstEndpoint: &coreDNS,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "dns", Protocol: 17,
		SrcAddr: coreDNS.Address, DstAddr: context.Source.Address,
		SrcPort: 53, DstPort: 54000, SrcEndpoint: &coreDNS,
	})
	dns := analyzer.DNS()
	if dns == nil || len(dns.Responders) != 1 || dns.Responders[0].Name != "coredns-abc" ||
		dns.BackendQueries != 1 || dns.BackendResponses != 1 ||
		!strings.Contains(dns.Conclusion, "between the source Pod and CoreDNS boundaries") {
		t.Fatalf("DNS activity = %#v", dns)
	}
}

func TestAnalyzerMarksUninstrumentedBackendUnavailable(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	context.Mode = model.TraceModeService
	context.BackendCoverageKnown = true
	context.InstrumentedBackends = nil
	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindStatus, Side: "backend", AttachmentID: "backend",
		Interface: "veth-backend", InterfaceIdx: 10,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", Protocol: 6,
		SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: context.Backends[0].Port,
		TCPFlags: 0x02, TCPSequence: 100,
	})

	for _, health := range analyzer.Health() {
		if health.Name == "backend/boundary" {
			if health.State != "UNAVAILABLE" || !strings.Contains(health.Detail, "--max-backends") {
				t.Fatalf("backend health = %#v", health)
			}
			datapath := analyzer.Datapath()
			if datapath == nil || !strings.Contains(datapath.Diagnosis, "--max-backends") {
				t.Fatalf("datapath diagnosis = %#v", datapath)
			}
			return
		}
	}
	t.Fatal("backend health missing")
}

func TestAnalyzerPrefersObservedBackendOverCoverageMetadata(t *testing.T) {
	analyzer := NewAnalyzer()
	context := testContext()
	context.Mode = model.TraceModeService
	context.BackendCoverageKnown = true
	context.InstrumentedBackends = nil
	now := time.Now()

	analyzer.Observe(model.Observation{Kind: model.KindTraceContext, Trace: &context})
	analyzer.Observe(model.Observation{
		Kind: model.KindStatus, Side: "backend", AttachmentID: "backend-1",
		Interface: "veth-backend", InterfaceIdx: 10,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "source", WallTime: now,
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Frontends[0].Address,
		SrcPort: 40000, DstPort: context.Frontends[0].Port,
		TCPFlags: 0x02, TCPSequence: 100,
	})
	analyzer.Observe(model.Observation{
		Kind: model.KindPacket, Side: "backend", WallTime: now.Add(time.Millisecond),
		Protocol: 6, SrcAddr: context.Source.Address, DstAddr: context.Backends[0].Address,
		SrcPort: 40000, DstPort: context.Backends[0].Port,
		TCPFlags: 0x02, TCPSequence: 100,
	})

	backendObserved := false
	for _, current := range analyzer.Health() {
		if current.Name == "backend/boundary" {
			backendObserved = true
			if current.State != "OBSERVED" {
				t.Fatalf("backend health = %#v", current)
			}
		}
	}
	if !backendObserved {
		t.Fatal("backend health missing")
	}
	datapath := analyzer.Datapath()
	if datapath == nil || datapath.DestinationBoundary.State != "OBSERVED" ||
		!strings.Contains(datapath.Diagnosis, "observed through the destination Pod boundary") {
		t.Fatalf("datapath = %#v", datapath)
	}
}

func testContext() model.TraceContext {
	dnsService := model.Endpoint{
		Kind: model.EndpointService, Namespace: "kube-system", Name: "kube-dns",
		Address: netip.MustParseAddr("fd00:96::53"), Port: 53,
	}
	return model.TraceContext{
		Source: model.Endpoint{
			Kind: model.EndpointPod, Namespace: "demo", Name: "client",
			Address: netip.MustParseAddr("fd00:10::10"),
		},
		Service: &model.Endpoint{Kind: model.EndpointService, Namespace: "demo", Name: "api"},
		Frontends: []model.Endpoint{{
			Kind: model.EndpointService, Namespace: "demo", Name: "api",
			Address: netip.MustParseAddr("fd00:96::10"), Port: 80,
		}},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "demo", Name: "api-abc",
			Address: netip.MustParseAddr("fd00:10::20"), Port: 8080,
		}},
		DNSService:   &dnsService,
		DNSFrontends: []model.Endpoint{dnsService},
		DNSBackends: []model.Endpoint{{
			Kind: model.EndpointPod, Namespace: "kube-system", Name: "coredns-abc",
			Address: netip.MustParseAddr("fd00:10::53"), Port: 53,
		}},
	}
}
