package tcx

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/SRodi/kubectl-datapath/internal/capture"
	"github.com/SRodi/kubectl-datapath/internal/model"
)

type ClassicStrategy struct{}

func (ClassicStrategy) Name() string { return "tc-clsact-veth" }

func (ClassicStrategy) Open(ctx context.Context, target capture.Target) (capture.Session, error) {
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
	if err := configureClassicObjects(&objects, target); err != nil {
		objects.Close()
		return nil, err
	}
	if err := ensureClsact(iface.Index); err != nil {
		objects.Close()
		return nil, err
	}
	ingress := classicFilter(iface.Index, netlink.HANDLE_MIN_INGRESS, objects.ObserveIngress.FD(), target)
	if err := netlink.FilterAdd(ingress); err != nil {
		objects.Close()
		return nil, fmt.Errorf("attach classic TC ingress: %w", err)
	}
	egress := classicFilter(iface.Index, netlink.HANDLE_MIN_EGRESS, objects.ObserveEgress.FD(), target)
	if err := netlink.FilterAdd(egress); err != nil {
		_ = netlink.FilterDel(ingress)
		objects.Close()
		return nil, fmt.Errorf("attach classic TC egress: %w", err)
	}
	attachments := []io.Closer{
		&filterCloser{filter: egress},
		&filterCloser{filter: ingress},
	}
	if target.CaptureConnect {
		connect, err := link.AttachTracing(link.TracingOptions{Program: objects.ObserveConnect})
		if err != nil {
			closeAll(attachments)
			objects.Close()
			return nil, fmt.Errorf("attach connect fentry: %w", err)
		}
		attachments = append(attachments, connect)
	}
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		closeAll(attachments)
		objects.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	session := &session{
		target:       target,
		objects:      objects,
		attachments:  attachments,
		reader:       reader,
		events:       make(chan model.Observation, 1024),
		errors:       make(chan error, 1),
		packetHooks:  []string{"tc/ingress", "tc/egress"},
		packetPoint:  "host-veth/tc",
		transitPoint: "node-transit/tc",
		hookEvidence: "classic TC hook",
	}
	go session.run(ctx)
	return session, nil
}

func configureClassicObjects(objects *bpfObjects, target capture.Target) error {
	if target.CaptureConnect && len(target.CgroupIDs) == 0 {
		return fmt.Errorf("connect capture requires at least one target cgroup")
	}
	enabled := uint8(1)
	for _, cgroupID := range target.CgroupIDs {
		if err := objects.TargetCgroups.Update(&cgroupID, &enabled, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("configure target cgroup %d: %w", cgroupID, err)
		}
	}
	for _, address := range target.FlowAddresses {
		key := addressKey(address)
		if err := objects.FlowAddresses.Update(&key, &enabled, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("configure flow address %s: %w", address, err)
		}
	}
	if target.Transit || len(target.FlowAddresses) > 0 {
		zero := uint32(0)
		mode := uint8(2)
		if target.Transit {
			mode = 1
		}
		if err := objects.CaptureModes.Update(&zero, &mode, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("configure capture mode: %w", err)
		}
	}
	return nil
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
	return netlink.FilterDel(c.filter)
}

func closeAll(closers []io.Closer) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}
