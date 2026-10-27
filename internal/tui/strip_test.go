package tui

import (
	"strings"
	"testing"

	"github.com/SRodi/kubectl-datapath/internal/model"
	traceview "github.com/SRodi/kubectl-datapath/internal/trace"
)

func attached(id, iface string, seen, emitted uint64) model.Observation {
	return model.Observation{
		AttachmentID: id, Interface: iface, Hooks: []string{"tcx/ingress", "tcx/egress"},
		Diagnostics: []model.HookDiagnostics{
			{Hook: "tcx/ingress", Seen: seen, Emitted: emitted},
			{Hook: "tcx/egress"},
		},
	}
}

func crossNodeView(source, destination string) (traceview.DatapathView, []model.Observation) {
	srcPod, dstPod := attached("src", "veth1", 1204, 12), attached("dst", "veth9", 3911, 0)
	view := traceview.DatapathView{
		CrossNode:            true,
		SourceBoundary:       traceview.EvidencePoint{State: source},
		SourceTransit:        &traceview.EvidencePoint{State: "OBSERVED"},
		DestinationTransit:   &traceview.EvidencePoint{State: "OBSERVED"},
		DestinationBoundary:  traceview.EvidencePoint{State: destination},
		SourceInterface:      srcPod,
		DestinationInterface: dstPod,
		SourceNode:           "a", DestinationNode: "b",
	}
	transitSource, transitDestination := attached("ts", "eth0", 98311, 12), attached("td", "eth0", 77020, 12)
	transitSource.Side, transitSource.Node = "transit-source", "a"
	transitDestination.Side, transitDestination.Node = "transit-destination", "b"
	return view, []model.Observation{srcPod, dstPod, transitSource, transitDestination}
}

func TestStripShowsAttachedIdleBeforeAnyTraffic(t *testing.T) {
	view, attachments := crossNodeView("NO EVIDENCE", "NO EVIDENCE")
	view.SourceTransit = &traceview.EvidencePoint{State: "NO EVIDENCE"}
	view.DestinationTransit = &traceview.EvidencePoint{State: "NO EVIDENCE"}
	points := buildStrip(view, attachments, 0, false)
	summary := summarize(points, view, false, false)
	if summary.badge != "WAITING" || summary.headline != "Waiting for traffic…" {
		t.Fatalf("idle hooks must not look like a gap: %+v", summary)
	}
	output := renderStrip(points, 0)
	if strings.Contains(output, "×") || strings.Contains(output, "●") || strings.Count(output, "attached, idle") != 4 {
		t.Fatalf("idle strip is wrong:\n%s", output)
	}
	if !strings.Contains(output, "seen 1,204") {
		t.Fatalf("hook counters missing before any match:\n%s", output)
	}
}

func TestStripLocalizesGapAndShowsCounters(t *testing.T) {
	view, attachments := crossNodeView("OBSERVED", "NO EVIDENCE")
	points := buildStrip(view, attachments, 36, false)
	summary := summarize(points, view, false, false)
	if summary.badge != "GAP FOUND" || summary.headline != "Evidence stops before dst Pod" {
		t.Fatalf("gap not localized: %+v", summary)
	}
	output := renderStrip(points, 0)
	for _, expected := range []string{"seen 3,911", "captured 0", "captured 12", "seen 98,311"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("%q missing:\n%s", expected, output)
		}
	}
}

func TestStripFlagsEventLossAndFallsBackToVerticalWhenNarrow(t *testing.T) {
	view, attachments := crossNodeView("OBSERVED", "NO EVIDENCE")
	view.SourceTransit = &traceview.EvidencePoint{State: "INCOMPLETE"}
	points := buildStrip(view, attachments, 36, false)
	if summary := summarize(points, view, false, false); summary.badge != "INCOMPLETE" ||
		summary.headline != "Events lost at src node" {
		t.Fatalf("loss not reported: %+v", summary)
	}
	narrow := renderStrip(points, 80)
	if lines := strings.Split(narrow, "\n"); len(lines) < len(points) || !strings.Contains(narrow, "veth9 tcx · seen 3,911") {
		t.Fatalf("narrow layout is not vertical:\n%s", narrow)
	}
}

func TestStripTreatsUnjudgedGapAsFinalOnceStreamCloses(t *testing.T) {
	view, attachments := crossNodeView("NO EVIDENCE", "NO EVIDENCE")
	points := buildStrip(view, attachments, 0, true)
	if summary := summarize(points, view, false, true); summary.badge != "GAP FOUND" {
		t.Fatalf("closed trace without evidence must not stay idle: %+v", summary)
	}
}
