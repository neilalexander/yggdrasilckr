//go:build linux

package routes

import (
	"fmt"

	"github.com/gologme/log"
	"github.com/vishvananda/netlink"

	"github.com/yggdrasil-network/yggdrasil-go/src/tun"
)

func SetRoutes(tun *tun.TunAdapter, log *log.Logger, cidrs []string) error {
	nlintf, err := netlink.LinkByName(tun.Name())
	if err != nil {
		return fmt.Errorf("failed to find link by name: %w", err)
	}
	for _, cidr := range cidrs {
		nladdr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return fmt.Errorf("couldn't parse CIDR %q: %w", cidr, err)
		}
		if err := netlink.RouteAdd(&netlink.Route{
			Dst:       nladdr.IPNet,
			LinkIndex: nlintf.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
		}); err != nil {
			log.Warnln("Failed to add route", cidr, "to routing table:", err)
		}
	}
	return nil
}
