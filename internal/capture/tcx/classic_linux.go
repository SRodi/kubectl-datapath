//go:build linux

package tcx

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/SRodi/kubectl-datapath/internal/capture"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

type ClassicStrategy struct{}

func (ClassicStrategy) Name() string { return "tc-clsact" }

func (ClassicStrategy) Open(ctx context.Context, target capture.Target) (capture.Session, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	if err := resolveInterface(&target); err != nil {
		return nil, err
	}
	var objects bpfObjects
	if err := loadBpfObjects(&objects, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	if err := configureCaptureObjects(&objects, target); err != nil {
		return nil, openError(err, nil, &objects)
	}
	if err := ensureClsact(int(target.InterfaceIndex)); err != nil {
		return nil, openError(err, nil, &objects)
	}
	ingress := classicFilter(int(target.InterfaceIndex), netlink.HANDLE_MIN_INGRESS, objects.ObserveIngress.FD(), target)
	if err := netlink.FilterAdd(ingress); err != nil {
		return nil, openError(fmt.Errorf("attach classic TC ingress: %w", err), nil, &objects)
	}
	egress := classicFilter(int(target.InterfaceIndex), netlink.HANDLE_MIN_EGRESS, objects.ObserveEgress.FD(), target)
	if err := netlink.FilterAdd(egress); err != nil {
		return nil, openError(
			fmt.Errorf("attach classic TC egress: %w", err),
			[]io.Closer{&filterCloser{filter: ingress}},
			&objects,
		)
	}
	attachments := []io.Closer{
		&filterCloser{filter: ingress},
		&filterCloser{filter: egress},
	}
	if target.CaptureConnect {
		connect, err := link.AttachTracing(link.TracingOptions{Program: objects.ObserveConnect})
		if err != nil {
			return nil, openError(fmt.Errorf("attach connect fentry: %w", err), attachments, &objects)
		}
		attachments = append(attachments, connect)
	}
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		return nil, openError(fmt.Errorf("open ring buffer: %w", err), attachments, &objects)
	}
	session := &session{
		target:       target,
		objects:      objects,
		attachments:  attachments,
		reader:       reader,
		events:       make(chan model.Observation, 1024),
		errors:       make(chan error, 1),
		packetHooks:  []string{"tc/ingress", "tc/egress"},
		packetPoint:  "pod-boundary/tc",
		transitPoint: "node-transit/tc",
		hookEvidence: "classic TC hook",
		done:         make(chan struct{}),
	}
	go session.run(ctx)
	return session, nil
}

func ensureClsact(linkIndex int) error {
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: linkIndex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("ensure clsact qdisc: %w", err)
	}
	return nil
}

func classicFilter(linkIndex int, parent uint32, fd int, target capture.Target) *netlink.BpfFilter {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(target.SessionID + "/" + target.AttachID))
	value := hash.Sum32()
	minor := uint16(value%0xfffe + 1)
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkIndex,
			Parent:    parent,
			Handle:    netlink.MakeHandle(1, minor),
			Priority:  uint16(40000 + value%20000),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           fd,
		Name:         fmt.Sprintf("kdp-%08x", value),
		DirectAction: true,
	}
}

type filterCloser struct {
	filter netlink.Filter
}

func (c *filterCloser) Close() error {
	err := netlink.FilterDel(c.filter)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}
