package ckriprwc

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/gologme/log"

	"github.com/neilalexander/yggdrasilckr/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

type cryptokey struct {
	log          *log.Logger
	config       *config.TunnelRoutingConfig
	enabled      atomic.Value // bool
	ipv4remotes  []cryptokey_route
	ipv6remotes  []cryptokey_route
	ipv4cache    map[address.Address]cryptokey_route
	ipv6cache    map[address.Address]cryptokey_route
	mutexremotes sync.RWMutex
	mutexcaches  sync.RWMutex
}

type cryptokey_route struct {
	subnet      net.IPNet
	destination ed25519.PublicKey
}

// Configure the CKR routes. This should only ever be ran by the TUN/TAP actor.
func (c *cryptokey) configure() error {
	// Set enabled/disabled state
	c.setEnabled(c.config.Enable)
	if !c.config.Enable {
		return nil
	}

	// Clear out existing routes
	c.mutexremotes.Lock()
	c.ipv6remotes = make([]cryptokey_route, 0, len(c.config.IPv6RemoteSubnets))
	c.ipv4remotes = make([]cryptokey_route, 0, len(c.config.IPv4RemoteSubnets))
	c.mutexremotes.Unlock()

	// Add IPv6 routes
	for ipv6, pubkey := range c.config.IPv6RemoteSubnets {
		if err := c.addRemoteSubnet(ipv6, pubkey); err != nil {
			return fmt.Errorf("Error adding CKR IPv6 remote subnet: %w", err)
		}
	}

	// Add IPv4 routes
	for ipv4, pubkey := range c.config.IPv4RemoteSubnets {
		if err := c.addRemoteSubnet(ipv4, pubkey); err != nil {
			return fmt.Errorf("Error adding CKR IPv4 remote subnet: %w", err)
		}
	}

	// Wipe the caches
	c.mutexcaches.Lock()
	c.ipv4cache = make(map[address.Address]cryptokey_route, len(c.config.IPv6RemoteSubnets))
	c.ipv6cache = make(map[address.Address]cryptokey_route, len(c.config.IPv4RemoteSubnets))
	c.mutexcaches.Unlock()

	return nil
}

// Enable or disable crypto-key routing.
func (c *cryptokey) setEnabled(enabled bool) {
	c.enabled.Store(enabled)
}

// Check if crypto-key routing is enabled.
func (c *cryptokey) isEnabled() bool {
	enabled, ok := c.enabled.Load().(bool)
	return ok && enabled
}

// Adds a destination route for the given CIDR to be tunnelled to the node
// with the given BoxPubKey.
func (c *cryptokey) addRemoteSubnet(cidr string, dest string) error {
	c.mutexremotes.Lock()
	c.mutexcaches.Lock()
	defer c.mutexremotes.Unlock()
	defer c.mutexcaches.Unlock()

	// Is the CIDR we've been given valid?
	ipaddr, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	// Get the prefix length and size
	_, prefixsize := ipnet.Mask.Size()

	// Build our references to the routing table and cache
	var routingtable *[]cryptokey_route
	var routingcache *map[address.Address]cryptokey_route

	// Check if the prefix is IPv4 or IPv6
	if prefixsize == net.IPv6len*8 {
		routingtable = &c.ipv6remotes
		routingcache = &c.ipv6cache
	} else if prefixsize == net.IPv4len*8 {
		routingtable = &c.ipv4remotes
		routingcache = &c.ipv4cache
	} else {
		return errors.New("unexpected prefix size")
	}

	// Is the route an Yggdrasil destination?
	var addr address.Address
	var snet address.Subnet
	copy(addr[:], ipaddr)
	copy(snet[:], ipnet.IP)
	if addr.IsValid() || snet.IsValid() {
		return errors.New("can't specify Yggdrasil destination as crypto-key route")
	}
	// Do we already have a route for this subnet?
	for _, route := range *routingtable {
		if route.subnet.String() == ipnet.String() {
			return fmt.Errorf("remote subnet already exists for %s", cidr)
		}
	}
	// Decode the public key
	if bpk, err := hex.DecodeString(dest); err != nil {
		return fmt.Errorf("hex.DecodeString: %w", err)
	} else if len(bpk) != ed25519.PublicKeySize {
		return fmt.Errorf("incorrect key length for %s", dest)
	} else {
		// Add the new crypto-key route
		key := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(key[:], bpk)
		*routingtable = append(*routingtable, cryptokey_route{
			subnet:      *ipnet,
			destination: key,
		})

		// Sort so most specific routes are first
		sort.Slice(*routingtable, func(i, j int) bool {
			im, _ := (*routingtable)[i].subnet.Mask.Size()
			jm, _ := (*routingtable)[j].subnet.Mask.Size()
			return im > jm
		})

		// Clear the cache as this route might change future routing
		// Setting an empty slice keeps the memory whereas nil invokes GC
		for k := range *routingcache {
			delete(*routingcache, k)
		}

		c.log.Infoln("Added CKR remote subnet", cidr)
		return nil
	}
}

// Looks up the most specific route for the given address (with the address
// length specified in bytes) from the crypto-key routing table. An error is
// returned if the address is not suitable or no route was found.
func (c *cryptokey) getPublicKeyForAddress(addr address.Address, addrlen int) (ed25519.PublicKey, error) {
	if !c.isEnabled() {
		return nil, fmt.Errorf("CKR not enabled")
	}

	// Check if the address is a valid Yggdrasil address - if so it
	// is exempt from all CKR checking
	if addr.IsValid() {
		return nil, errors.New("cannot look up CKR for Yggdrasil addresses")
	}

	// Build our references to the routing table and cache
	var routingtable *[]cryptokey_route
	var routingcache *map[address.Address]cryptokey_route

	// Check if the prefix is IPv4 or IPv6
	if addrlen == net.IPv6len {
		routingcache = &c.ipv6cache
	} else if addrlen == net.IPv4len {
		routingcache = &c.ipv4cache
	} else {
		return nil, errors.New("unexpected prefix size")
	}

	// Check if there's a cache entry for this addr
	c.mutexcaches.RLock()
	if route, ok := (*routingcache)[addr]; ok {
		c.mutexcaches.RUnlock()
		return route.destination, nil
	}
	c.mutexcaches.RUnlock()

	c.mutexremotes.RLock()
	defer c.mutexremotes.RUnlock()

	// Check if the prefix is IPv4 or IPv6
	if addrlen == net.IPv6len {
		routingtable = &c.ipv6remotes
	} else if addrlen == net.IPv4len {
		routingtable = &c.ipv4remotes
	} else {
		return nil, errors.New("unexpected prefix size")
	}

	// No cache was found - start by converting the address into a net.IP
	ip := make(net.IP, addrlen)
	copy(ip[:addrlen], addr[:])

	// Check if we have a route. At this point c.ipv6remotes should be
	// pre-sorted so that the most specific routes are first
	for _, route := range *routingtable {
		// Does this subnet match the given IP?
		if route.subnet.Contains(ip) {
			c.mutexcaches.Lock()
			defer c.mutexcaches.Unlock()

			// Check if the routing cache is above a certain size, if it is evict
			// a random entry so we can make room for this one. We take advantage
			// of the fact that the iteration order is random here
			for k := range *routingcache {
				if len(*routingcache) < 1024 {
					break
				}
				delete(*routingcache, k)
			}

			// Cache the entry for future packets to get a faster lookup
			(*routingcache)[addr] = route

			// Return the boxPubKey
			return route.destination, nil
		}
	}

	// No route was found if we got to this point
	return ed25519.PublicKey{}, fmt.Errorf("no route to %s", ip.String())
}
