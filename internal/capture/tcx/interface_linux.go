//go:build linux

package tcx

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/SRodi/kubectl-datapath/internal/capture"
)

func resolveInterface(target *capture.Target) error {
	device, err := netlink.LinkByName(target.Interface)
	if err != nil {
		return fmt.Errorf("resolve interface %q: %w", target.Interface, err)
	}
	target.InterfaceIndex = uint32(device.Attrs().Index)
	target.InterfaceKind = device.Type()
	target.InterfaceMode = ""
	if netkit, ok := device.(*netlink.Netkit); ok {
		switch netkit.Mode {
		case netlink.NETKIT_MODE_L2:
			target.InterfaceMode = "L2"
		case netlink.NETKIT_MODE_L3:
			target.InterfaceMode = "L3"
		default:
			return fmt.Errorf("interface %q has unsupported netkit mode %d", target.Interface, netkit.Mode)
		}
	}
	if device.Attrs().MasterIndex != 0 {
		master, err := netlink.LinkByIndex(device.Attrs().MasterIndex)
		if err != nil {
			return fmt.Errorf("resolve master for interface %q: %w", target.Interface, err)
		}
		target.InterfaceMaster = master.Attrs().Name
		if vrf, ok := master.(*netlink.Vrf); ok {
			target.InterfaceVRFTable = vrf.Table
		}
	}
	return nil
}
