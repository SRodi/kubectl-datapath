package tui

import (
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func attemptPacketContext() model.TraceContext {
	return model.TraceContext{
		Mode: model.TraceModeService,
		Source: model.Endpoint{
			Kind: model.EndpointPod, Name: "same-a", Node: "worker",
			Address: netip.MustParseAddr("10.244.2.10"),
		},
		Frontends: []model.Endpoint{{
			Kind: model.EndpointService, Name: "cross-service",
			Address: netip.MustParseAddr("10.96.30.10"), Port: 80,
		}},
		Backends: []model.Endpoint{{
			Kind: model.EndpointPod, Name: "cross-b", Node: "worker2",
			Address: netip.MustParseAddr("10.244.1.7"), Port: 8080,
		}},
	}
}

func attemptPacketExchange(context model.TraceContext, side string, initial uint32, start uint64) []model.Observation {
	node, target := context.Source.Node, context.Frontends[0]
	wall := time.Date(2026, 10, 9, 13, 56, 52, 0, time.UTC)
	if side == "backend" {
		node, target = context.Backends[0].Node, context.Backends[0]
		wall = wall.Add(-time.Hour)
	}
	const serverSequence uint32 = 30000
	specs := []struct {
		reply bool
		flags uint8
		seq   uint32
		ack   uint32
	}{
		{false, 0x02, initial, 0},
		{true, 0x12, serverSequence, initial + 1},
		{false, 0x10, initial + 1, serverSequence + 1},
		{false, 0x18, initial + 1, serverSequence + 1},
		{true, 0x10, serverSequence + 1, initial + 90},
		{true, 0x18, serverSequence + 1, initial + 90},
		{false, 0x10, initial + 90, serverSequence + 114},
		{true, 0x18, serverSequence + 114, initial + 90},
		{false, 0x10, initial + 90, serverSequence + 125},
		{false, 0x11, initial + 90, serverSequence + 125},
		{true, 0x11, serverSequence + 125, initial + 91},
		{false, 0x10, initial + 91, serverSequence + 126},
	}
	var events []model.Observation
	for i, spec := range specs {
		event := model.Observation{
			Kind: model.KindPacket, Side: side, Node: node, AttachmentID: side,
			Protocol: 6, SrcAddr: context.Source.Address, SrcPort: 47858,
			DstAddr: target.Address, DstPort: target.Port,
			TCPFlags: spec.flags, TCPSequence: spec.seq, TCPAck: spec.ack,
			MonotonicNS: start + uint64(i), WallTime: wall.Add(time.Duration(start+uint64(i)) * time.Millisecond),
			Point: "pod-boundary/tcx",
		}
		if spec.reply {
			event.SrcAddr, event.DstAddr = event.DstAddr, event.SrcAddr
			event.SrcPort, event.DstPort = event.DstPort, event.SrcPort
		}
		events = append(events, event)
	}
	return events
}

func updateAttemptPackets(m Model, events ...model.Observation) Model {
	for _, event := range events {
		updated, _ := m.Update(observationMsg{observation: event})
		m = updated.(Model)
	}
	return m
}

func newAttemptPacketModel(context model.TraceContext) Model {
	return updateAttemptPackets(New("trace", make(chan model.Observation), make(chan error)),
		model.Observation{Kind: model.KindTraceContext, Trace: &context})
}

func assertAttemptPackets(t *testing.T, got, want []model.Observation) {
	t.Helper()
	got = append([]model.Observation(nil), got...)
	want = append([]model.Observation(nil), want...)
	for _, events := range [][]model.Observation{got, want} {
		sort.Slice(events, func(i, j int) bool {
			if events[i].Node != events[j].Node {
				return events[i].Node < events[j].Node
			}
			return observationBefore(events[i], events[j])
		})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("attempt packets differ: got %d, want %d\n got: %+v\nwant: %+v", len(got), len(want), got, want)
	}
}

func TestServiceAttemptPacketsIndependentOfNodeArrivalOrder(t *testing.T) {
	context := attemptPacketContext()
	source := attemptPacketExchange(context, "source", 100, 1000)
	backend := attemptPacketExchange(context, "backend", 100, 100)
	var interleaved []model.Observation
	for i := range source {
		interleaved = append(interleaved, backend[i], source[i])
	}
	for name, events := range map[string][]model.Observation{
		"source-first":  append(append([]model.Observation(nil), source...), backend...),
		"backend-first": append(append([]model.Observation(nil), backend...), source...),
		"interleaved":   interleaved,
	} {
		t.Run(name, func(t *testing.T) {
			m := updateAttemptPackets(newAttemptPacketModel(context), events...)
			want := append(append([]model.Observation(nil), source...), backend...)
			assertAttemptPackets(t, m.currentPackets(), want)
			view := m.View()
			if !strings.Contains(view, "showing 1-24 of 24 observations") ||
				strings.Count(view, "PSH-ACK") != 6 || strings.Count(view, "FIN-ACK") != 4 {
				t.Fatalf("full exchange is not rendered:\n%s", view)
			}
			assertAttemptPackets(t, m.currentPackets(), want)
		})
	}
}

func TestServiceAttemptPacketsReassociateAfterLateHandshake(t *testing.T) {
	context := attemptPacketContext()
	source := attemptPacketExchange(context, "source", 100, 1000)
	backend := attemptPacketExchange(context, "backend", 100, 100)
	m := updateAttemptPackets(newAttemptPacketModel(context), backend[2:]...)
	m = updateAttemptPackets(m, source...)
	assertAttemptPackets(t, m.currentPackets(), source)
	m = updateAttemptPackets(m, backend[1], backend[0])
	assertAttemptPackets(t, m.currentPackets(), append(source, backend...))
}

func TestServiceAttemptPacketsSeparateReusedPortsAcrossDelayedStreams(t *testing.T) {
	context := attemptPacketContext()
	oldSource := attemptPacketExchange(context, "source", 100, 1000)
	newSource := attemptPacketExchange(context, "source", 10000, 2000)
	oldBackend := attemptPacketExchange(context, "backend", 100, 100)
	newBackend := attemptPacketExchange(context, "backend", 10000, 200)
	for name, batches := range map[string][][]model.Observation{
		"source-first":        {oldSource, newSource, oldBackend, newBackend},
		"backend-first":       {oldBackend, newBackend, oldSource, newSource},
		"old-streams-delayed": {newSource, newBackend, oldBackend, oldSource},
	} {
		t.Run(name, func(t *testing.T) {
			m := newAttemptPacketModel(context)
			for _, events := range batches {
				m = updateAttemptPackets(m, events...)
			}
			assertAttemptPackets(t, m.currentPackets(), append(newSource, newBackend...))
			oldKey := attemptDisplayKey(6, context.Source.Address, 47858, 100)
			assertAttemptPackets(t, serviceAttemptPackets(m.packets, context, oldKey), append(oldSource, oldBackend...))
		})
	}
}

func TestNewBackendAttemptDoesNotBorrowActiveSourceAttempt(t *testing.T) {
	context := attemptPacketContext()
	oldSource := attemptPacketExchange(context, "source", 100, 1000)
	oldBackend := attemptPacketExchange(context, "backend", 100, 100)
	newSource := attemptPacketExchange(context, "source", 10000, 2000)
	newBackend := attemptPacketExchange(context, "backend", 10000, 200)
	m := updateAttemptPackets(newAttemptPacketModel(context), oldSource...)
	m = updateAttemptPackets(m, oldBackend...)
	m = updateAttemptPackets(m, newBackend...)
	assertAttemptPackets(t, m.currentPackets(), append(oldSource, oldBackend...))
	m = updateAttemptPackets(m, newSource...)
	assertAttemptPackets(t, m.currentPackets(), append(newSource, newBackend...))
}

func TestServiceAttemptPacketsSeparateSameNodeBoundaries(t *testing.T) {
	context := attemptPacketContext()
	context.Backends[0].Node = context.Source.Node
	source := attemptPacketExchange(context, "source", 100, 1000)
	backend := attemptPacketExchange(context, "backend", 100, 1100)
	for i := range source {
		if source[i].DstAddr == context.Frontends[0].Address {
			source[i].DstAddr, source[i].DstPort = context.Backends[0].Address, context.Backends[0].Port
		} else {
			source[i].SrcAddr, source[i].SrcPort = context.Backends[0].Address, context.Backends[0].Port
		}
	}
	m := updateAttemptPackets(newAttemptPacketModel(context), backend[2:]...)
	m = updateAttemptPackets(m, source...)
	assertAttemptPackets(t, m.currentPackets(), source)
	m = updateAttemptPackets(m, backend[:2]...)
	assertAttemptPackets(t, m.currentPackets(), append(source, backend...))
}

func TestServiceAttemptPacketsKeepEstablishedResetWithItsAttempt(t *testing.T) {
	context := attemptPacketContext()
	source := attemptPacketExchange(context, "source", 100, 1000)
	reset := source[len(source)-2]
	reset.TCPFlags = 0x14
	reset.MonotonicNS += 10
	reset.WallTime = reset.WallTime.Add(time.Second)
	m := updateAttemptPackets(newAttemptPacketModel(context), source...)
	m = updateAttemptPackets(m, reset)
	assertAttemptPackets(t, m.currentPackets(), append(source, reset))
}
