package ckriprwc

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/gologme/log"

	"github.com/neilalexander/yggdrasilckr/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

type cryptokey struct {
	log          *log.Logger
	sync.RWMutex // Protects the below.
	config       *config.TunnelRoutingConfig
	v4Routes     []*route
	v6Routes     []*route
}

type route struct {
	prefix      netip.Prefix
	destination ed25519.PublicKey
}

// Configure the CKR routes. This should only ever be ran by the TUN/TAP actor.
func (c *cryptokey) configure(config *config.TunnelRoutingConfig) error {
	c.Lock()
	defer c.Unlock()

	if c.config = config; !c.config.Enable {
		return nil
	}

	c.v4Routes = make([]*route, 0, len(c.config.IPv4RemoteSubnets))
	c.v6Routes = make([]*route, 0, len(c.config.IPv6RemoteSubnets))

	for ipv6, pubkey := range c.config.IPv6RemoteSubnets {
		if err := c._addRemoteSubnet(ipv6, pubkey); err != nil {
			c.log.Warnf("Error adding routed IPv6 subnet %q: %s", ipv6, err)
		}
	}

	for ipv4, pubkey := range c.config.IPv4RemoteSubnets {
		if err := c._addRemoteSubnet(ipv4, pubkey); err != nil {
			c.log.Warnf("Error adding routed IPv4 subnet %q: %s", ipv4, err)
		}
	}

	for pubkey, ips := range c.config.RemoteSubnets {
		for _, ip := range ips {
			if err := c._addRemoteSubnet(ip, pubkey); err != nil {
				c.log.Warnf("Error adding routed subnet %q: %s", ip, err)
			}
		}
	}

	if len(c.v6Routes) > 0 {
		sort.Slice(c.v6Routes, func(i, j int) bool {
			return sortRoutes(c.v6Routes, i, j)
		})

		c.log.Println("Active IPv6 routes:")
		for _, r := range c.v6Routes {
			c.log.Println(" -", r.prefix, "via", hex.EncodeToString(r.destination))
		}
	} else {
		c.log.Println("No active IPv6 routes")
	}

	if len(c.v4Routes) > 0 {
		sort.Slice(c.v4Routes, func(i, j int) bool {
			return sortRoutes(c.v4Routes, i, j)
		})

		c.log.Println("Active IPv4 routes:")
		for _, r := range c.v4Routes {
			c.log.Println(" -", r.prefix, "via", hex.EncodeToString(r.destination))
		}
	} else {
		c.log.Println("No active IPv4 routes")
	}

	return nil
}

// Adds a destination route for the given CIDR to be tunnelled to the node
// with the given BoxPubKey. Write lock must be held.
func (c *cryptokey) _addRemoteSubnet(cidr string, dest string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}

	bpk, err := hex.DecodeString(dest)
	if err != nil {
		return fmt.Errorf("hex.DecodeString: %w", err)
	} else if len(bpk) != ed25519.PublicKeySize {
		return fmt.Errorf("incorrect key length for %q", dest)
	}

	is4, is6 := prefix.Addr().Is4(), prefix.Addr().Is6()
	switch {
	case is6:
		if isYggdrasilDestination(prefix.Addr()) {
			return errors.New("can't specify Yggdrasil destination as routed subnet")
		}
		for _, route := range c.v6Routes {
			if route.prefix == prefix {
				return fmt.Errorf("remote subnet already exists for %s", cidr)
			}
		}
		c.v6Routes = append(c.v6Routes, &route{
			prefix:      prefix,
			destination: append(ed25519.PublicKey{}, bpk...),
		})

	case is4:
		for _, route := range c.v4Routes {
			if route.prefix == prefix {
				return fmt.Errorf("remote subnet already exists for %s", cidr)
			}
		}
		c.v4Routes = append(c.v4Routes, &route{
			prefix:      prefix,
			destination: append(ed25519.PublicKey{}, bpk...),
		})

	default:
		return fmt.Errorf("unexpected prefix size")
	}

	return nil
}

// Sorts the routes so that the most specific prefixes always come before
// the less specific ones.
func sortRoutes(route []*route, i, j int) bool {
	pli, plj := route[i].prefix.Bits(), route[j].prefix.Bits()
	switch {
	case pli > plj:
		return true
	case pli < plj:
		return false
	default:
		return route[i].prefix.Addr().Less(route[j].prefix.Addr())
	}
}

// Looks up the most specific route for the given address (with the address
// length specified in bytes) from the crypto-key routing table. An error is
// returned if the address is not suitable or no route was found.
func (c *cryptokey) getPublicKeyForAddress(addr netip.Addr) (ed25519.PublicKey, error) {
	is4, is6 := addr.Is4(), addr.Is6()
	if is6 && isYggdrasilDestination(addr) {
		return nil, fmt.Errorf("can't get public key for Yggdrasil route")
	}

	c.RLock()
	defer c.RUnlock()

	var routes []*route
	switch {
	case is6:
		routes = c.v6Routes
	case is4:
		routes = c.v4Routes
	default:
		return nil, fmt.Errorf("unexpected prefix size")
	}

	for _, route := range routes {
		if route.prefix.Contains(addr) {
			return route.destination, nil
		}
	}

	return nil, fmt.Errorf("no route to %s", addr.String())
}

func isYggdrasilDestination(ip netip.Addr) bool {
	var addr address.Address
	var snet address.Subnet
	copy(addr[:], ip.AsSlice())
	copy(snet[:], ip.AsSlice())
	return addr.IsValid() || snet.IsValid()
}
