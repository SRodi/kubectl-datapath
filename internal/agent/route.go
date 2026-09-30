package agent

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

func InterfaceForRoute(destination netip.Addr) (string, error) {
	routes, err := netlink.RouteGet(net.IP(destination.AsSlice()))
	if err != nil {
		return "", fmt.Errorf("route lookup for %s: %w", destination, err)
	}
	for _, route := range routes {
		if route.LinkIndex == 0 {
			continue
		}
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			return "", fmt.Errorf("resolve route interface %d: %w", route.LinkIndex, err)
		}
		return link.Attrs().Name, nil
	}
	return "", fmt.Errorf("route lookup for %s returned no interface", destination)
}
