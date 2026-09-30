package tcx

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/SRodi/kubectl-datapath/internal/capture"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

type Strategy struct{}

func (Strategy) Name() string { return "tcx-veth" }

func (Strategy) Open(ctx context.Context, target capture.Target) (capture.Session, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	iface, err := net.InterfaceByName(target.Interface)
	if err != nil {
		return nil, fmt.Errorf("resolve interface %q: %w", target.Interface, err)
	}
	target.InterfaceIndex = uint32(iface.Index)
	var objects bpfObjects
	if err := loadBpfObjects(&objects, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	if target.CaptureConnect && len(target.CgroupIDs) == 0 {
		objects.Close()
		return nil, fmt.Errorf("connect capture requires at least one target cgroup")
	}
	enabled := uint8(1)
	for _, cgroupID := range target.CgroupIDs {
		if err := objects.TargetCgroups.Update(&cgroupID, &enabled, ebpf.UpdateAny); err != nil {
			objects.Close()
			return nil, fmt.Errorf("configure target cgroup %d: %w", cgroupID, err)
		}
	}
	if len(target.FlowAddresses) > 0 {
		for _, address := range target.FlowAddresses {
			key := addressKey(address)
			if err := objects.FlowAddresses.Update(&key, &enabled, ebpf.UpdateAny); err != nil {
				objects.Close()
				return nil, fmt.Errorf("configure flow address %s: %w", address, err)
			}
		}
	}
	if target.Transit || len(target.FlowAddresses) > 0 {
		zero := uint32(0)
		mode := uint8(2)
		// Transit takes precedence when a target also carries Pod flow filters.
		if target.Transit {
			mode = 1
		}
		if err := objects.CaptureModes.Update(&zero, &mode, ebpf.UpdateAny); err != nil {
			objects.Close()
			return nil, fmt.Errorf("configure capture mode: %w", err)
		}
	}
	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objects.ObserveEgress,
		Attach:    ebpf.AttachTCXEgress,
		Anchor:    link.Head(),
	})
	if err != nil {
		objects.Close()
		return nil, fmt.Errorf("attach TCX egress: %w", err)
	}
	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objects.ObserveIngress,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})
	if err != nil {
		egress.Close()
		objects.Close()
		return nil, fmt.Errorf("attach TCX ingress: %w", err)
	}
	links := []link.Link{ingress, egress}
	if target.CaptureConnect {
		connect, err := link.AttachTracing(link.TracingOptions{Program: objects.ObserveConnect})
		if err != nil {
			ingress.Close()
			egress.Close()
			objects.Close()
			return nil, fmt.Errorf("attach connect fentry: %w", err)
		}
		links = append(links, connect)
	}
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		for _, attached := range links {
			attached.Close()
		}
		objects.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	session := &session{
		target:  target,
		objects: objects,
		links:   links,
		reader:  reader,
		events:  make(chan model.Observation, 1024),
		errors:  make(chan error, 1),
	}
	go session.run(ctx)
	return session, nil
}

type session struct {
	target  capture.Target
	objects bpfObjects
	links   []link.Link
	reader  *ringbuf.Reader
	events  chan model.Observation
	errors  chan error
	once    sync.Once
}

func (s *session) Events() <-chan model.Observation { return s.events }
func (s *session) Errors() <-chan error             { return s.errors }

func (s *session) run(ctx context.Context) {
	// Stop loss reporting before closing outputs; closing the reader below unblocks a pending Read.
	reporterDone := make(chan struct{})
	var reporter sync.WaitGroup
	reporter.Add(1)
	go func() {
		defer reporter.Done()
		s.reportLoss(ctx, reporterDone)
	}()
	defer func() {
		close(reporterDone)
		reporter.Wait()
		close(s.events)
		close(s.errors)
	}()
	go func() {
		<-ctx.Done()
		s.reader.Close()
	}()
	// This offset is node-local; converted wall times must not order observations across nodes.
	offset := time.Now().UnixNano() - monotonicNow()
	hooks := []string{"tcx/ingress", "tcx/egress"}
	if s.target.CaptureConnect {
		hooks = append(hooks, "fentry/__sys_connect")
	}

	select {
	case s.events <- model.Observation{
		SchemaVersion: model.SchemaVersion,
		Kind:          model.KindStatus,
		SessionID:     s.target.SessionID,
		AttachmentID:  s.target.AttachID,
		Side:          s.target.Side,
		Node:          s.target.Node,
		WallTime:      time.Now(),
		Interface:     s.target.Interface,
		InterfaceIdx:  s.target.InterfaceIndex,
		CgroupIDs:     append([]uint64(nil), s.target.CgroupIDs...),
		Hooks:         hooks,
		Confidence:    model.ConfidenceExact,
		Message:       fmt.Sprintf("attachment ready: interface=%s hooks=%v cgroups=%d", s.target.Interface, hooks, len(s.target.CgroupIDs)),
	}:
	case <-ctx.Done():
		return
	}
	for {
		record, err := s.reader.Read()
		if err != nil {
			if ctx.Err() == nil && err != ringbuf.ErrClosed {
				s.errors <- fmt.Errorf("read ring buffer: %w", err)
			}
			return
		}
		var raw bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &raw); err != nil {
			s.errors <- fmt.Errorf("decode BPF event: %w", err)
			return
		}
		observation := observationFromRaw(s.target, raw, offset)
		select {
		case s.events <- observation:
		case <-ctx.Done():
			return
		}

	}
}

func (s *session) reportLoss(ctx context.Context, done <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var reported uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			zero := uint32(0)
			var lost uint64
			if err := s.objects.Losses.Lookup(&zero, &lost); err != nil {
				select {
				case s.errors <- fmt.Errorf("read loss counter: %w", err):
				default:
				}
				return
			}
			if lost == reported {
				continue
			}
			reported = lost
			hooks := []string{"tcx/ingress", "tcx/egress"}
			if s.target.CaptureConnect {
				hooks = append(hooks, "fentry/__sys_connect")
			}
			select {
			case s.events <- model.Observation{
				SchemaVersion: model.SchemaVersion,
				Kind:          model.KindStatus,
				SessionID:     s.target.SessionID,
				AttachmentID:  s.target.AttachID,
				Side:          s.target.Side,
				Node:          s.target.Node,
				WallTime:      time.Now(),
				Lost:          lost,
				Interface:     s.target.Interface,
				InterfaceIdx:  s.target.InterfaceIndex,
				CgroupIDs:     append([]uint64(nil), s.target.CgroupIDs...),
				Hooks:         hooks,
				Confidence:    model.ConfidenceExact,
				Message:       fmt.Sprintf("event loss=%d", lost),
			}:
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}
}

func observationFromRaw(target capture.Target, raw bpfEvent, wallOffset int64) model.Observation {
	kind := model.KindPacket
	point := "host-veth/tcx"
	evidence := []string{"attached interface", "TCX hook"}
	if raw.Kind == 2 {
		kind = model.KindConnect
		point = "application/connect"
		evidence = []string{"connect syscall", "target cgroup"}
	} else if raw.Kind == 3 {
		kind = model.KindTransit
		point = "node-transit/tcx"
		evidence = []string{"route-selected interface", "TCX hook", "selected inner tuple"}
	}
	observation := model.Observation{
		SchemaVersion: model.SchemaVersion,
		Kind:          kind,
		SessionID:     target.SessionID,
		AttachmentID:  target.AttachID,
		Side:          target.Side,
		Node:          target.Node,
		Point:         point,
		MonotonicNS:   raw.MonotonicNs,
		WallTime:      time.Unix(0, wallOffset+int64(raw.MonotonicNs)),
		Sequence:      raw.Sequence,
		Lost:          raw.Lost,
		Family:        raw.Family,
		Protocol:      raw.Protocol,
		DstAddr:       decodeAddress(raw.Family, raw.DstAddr),
		SrcPort:       raw.SrcPort,
		DstPort:       raw.DstPort,
		PacketLength:  raw.PacketLength,
		TCPFlags:      raw.TcpFlags,
		TCPSequence:   raw.TcpSequence,
		TCPAck:        raw.TcpAck,
		CgroupID:      raw.CgroupId,
		Interface:     target.Interface,
		InterfaceIdx:  raw.Ifindex,
		Confidence:    model.ConfidenceExact,
		Evidence:      evidence,
	}
	if kind == model.KindPacket || kind == model.KindTransit {
		observation.SrcAddr = decodeAddress(raw.Family, raw.SrcAddr)
		if raw.Direction == 1 {
			observation.Direction = model.DirectionIngress
		} else {
			observation.Direction = model.DirectionEgress
		}
	}
	if kind == model.KindTransit {
		observation.Confidence = model.ConfidenceCorrelated
		observation.TunnelID = raw.TunnelId
		observation.OuterFamily = raw.OuterFamily
		observation.OuterSrcPort = raw.OuterSrcPort
		observation.OuterDstPort = raw.OuterDstPort
		if raw.OuterFamily != 0 {
			observation.OuterSrcAddr = decodeAddress(raw.OuterFamily, raw.OuterSrcAddr)
			observation.OuterDstAddr = decodeAddress(raw.OuterFamily, raw.OuterDstAddr)
		}
		switch raw.Encapsulation {
		case 1:
			observation.Encapsulation = model.EncapsulationNative
		case 2:
			observation.Encapsulation = model.EncapsulationVXLAN
		}
	}
	return observation
}

type flowAddressKey struct {
	Family uint8
	Addr   [16]uint8
}

func addressKey(address netip.Addr) flowAddressKey {
	key := flowAddressKey{}
	if address.Is4() {
		key.Family = 4
		value := address.As4()
		copy(key.Addr[:], value[:])
		return key
	}
	key.Family = 6
	key.Addr = address.As16()
	return key
}

func decodeAddress(family uint8, raw [16]uint8) netip.Addr {
	if family == 4 {
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]})
	}
	return netip.AddrFrom16(raw)
}

func monotonicNow() int64 {
	var current unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &current); err != nil {
		return 0
	}
	return current.Nano()
}

func (s *session) Close() error {
	s.once.Do(func() {
		s.reader.Close()
		for _, attached := range s.links {
			attached.Close()
		}
		s.objects.Close()
	})
	return nil
}
