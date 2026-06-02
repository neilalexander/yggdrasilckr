//go:build darwin

package routes

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/gologme/log"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/yggdrasil-network/yggdrasil-go/src/tun"
)

func SetAddresses(tun *tun.TunAdapter, log *log.Logger, addresses []string) error {
	for _, cidr := range addresses {
		if err := addAddressDarwin(tun, cidr); err != nil {
			log.Warnln("Failed to add address", cidr, "to interface:", err)
		}
	}
	return nil
}

func SetRoutes(tun *tun.TunAdapter, log *log.Logger, cidrs []string) error {
	iface, err := net.InterfaceByName(tun.Name())
	if err != nil {
		return fmt.Errorf("failed to find link by name: %w", err)
	}

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("failed to open routing socket: %w", err)
	}
	defer unix.Close(fd)

	for i, cidr := range cidrs {
		if err := addRouteDarwin(fd, iface, cidr, i+1); err != nil {
			log.Warnln("Failed to add route", cidr, "to routing table:", err)
		}
	}
	return nil
}

func addAddressDarwin(tun *tun.TunAdapter, cidr string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("couldn't parse CIDR %q: %w", cidr, err)
	}

	if ip4 := ip.To4(); ip4 != nil {
		if err := addAddressDarwinIPv4(tun, ip4, ipnet.Mask); err != nil {
			return fmt.Errorf("couldn't add address %q: %w", cidr, err)
		}
		return nil
	}

	if err := addAddressDarwinIPv6(tun, ip.To16(), ipnet.Mask); err != nil {
		return fmt.Errorf("couldn't add address %q: %w", cidr, err)
	}
	return nil
}

func addRouteDarwin(fd int, iface *net.Interface, cidr string, seq int) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("couldn't parse CIDR %q: %w", cidr, err)
	}

	msg := &route.RouteMessage{
		Version: syscall.RTM_VERSION,
		Type:    unix.RTM_ADD,
		Flags:   syscall.RTF_UP | syscall.RTF_STATIC,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   make([]route.Addr, unix.RTAX_MAX),
	}
	if ip4 := ipnet.IP.To4(); ip4 != nil {
		var dst [4]byte
		copy(dst[:], ip4)
		var mask [4]byte
		copy(mask[:], ipnet.Mask)
		msg.Addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: dst}
		msg.Addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: mask}
	} else {
		var dst [16]byte
		copy(dst[:], ipnet.IP.To16())
		var mask [16]byte
		copy(mask[:], ipnet.Mask)
		msg.Addrs[unix.RTAX_DST] = &route.Inet6Addr{IP: dst}
		msg.Addrs[unix.RTAX_NETMASK] = &route.Inet6Addr{IP: mask}
	}
	msg.Addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{
		Index: iface.Index,
		Name:  iface.Name,
		Addr:  iface.HardwareAddr,
	}

	b, err := msg.Marshal()
	if err != nil {
		return fmt.Errorf("couldn't marshal route %q: %w", cidr, err)
	}
	if _, err := unix.Write(fd, b); err != nil {
		return fmt.Errorf("couldn't add route %q: %w", cidr, err)
	}

	var ackBuf [4096]byte
	n, err := unix.Read(fd, ackBuf[:])
	if err != nil {
		return fmt.Errorf("couldn't read route ack for %q: %w", cidr, err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, ackBuf[:n])
	if err != nil {
		return fmt.Errorf("couldn't parse route ack for %q: %w", cidr, err)
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rm.ID != uintptr(os.Getpid()) || rm.Seq != seq {
			continue
		}
		if rm.Err != nil {
			return fmt.Errorf("%w", rm.Err)
		}
		return nil
	}
	return nil
}

func addAddressDarwinIPv4(tun *tun.TunAdapter, ip net.IP, mask net.IPMask) error {
	iface, err := net.InterfaceByName(tun.Name())
	if err != nil {
		return fmt.Errorf("failed to find link by name: %w", err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to open AF_INET socket: %w", err)
	}
	defer unix.Close(fd)

	ones, _ := mask.Size()
	broadcast := net.IPv4zero
	if ones > 0 && ones < 32 {
		broadcast = broadcastIPv4(ip, mask)
	} else {
		broadcast = ip
	}

	var ar inAliasReq
	copy(ar.IfraName[:], iface.Name)
	ar.IfraAddr = sockAddrInet4FromIP(ip)
	ar.IfraBroadAddr = sockAddrInet4FromIP(broadcast)
	ar.IfraMask = sockAddrInet4FromMask(mask)

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCAIFADDR), uintptr(unsafe.Pointer(&ar))); errno != 0 {
		return fmt.Errorf("failed to call SIOCAIFADDR: %w", errno)
	}
	return nil
}

func addAddressDarwinIPv6(tun *tun.TunAdapter, ip net.IP, mask net.IPMask) error {
	iface, err := net.InterfaceByName(tun.Name())
	if err != nil {
		return fmt.Errorf("failed to find link by name: %w", err)
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to open AF_INET6 socket: %w", err)
	}
	defer unix.Close(fd)

	var ar in6AliasReq
	copy(ar.IfraName[:], iface.Name)
	ar.IfraAddr = sockAddrInet6FromIP(ip)
	ar.IfraPrefixMask = sockAddrInet6FromMask(mask)
	ar.IfraFlags |= darwin_IN6_IFF_NODAD
	ar.IfraFlags |= darwin_IN6_IFF_SECURED
	ar.IfraLifetime.Ia6tVltime = darwin_ND6_INFINITE_LIFETIME
	ar.IfraLifetime.Ia6tPltime = darwin_ND6_INFINITE_LIFETIME

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(darwin_SIOCAIFADDR_IN6), uintptr(unsafe.Pointer(&ar))); errno != 0 {
		return fmt.Errorf("failed to call SIOCAIFADDR_IN6: %w", errno)
	}
	return nil
}

type inAliasReq struct {
	IfraName      [syscall.IFNAMSIZ]byte
	IfraAddr      syscall.RawSockaddrInet4
	IfraBroadAddr syscall.RawSockaddrInet4
	IfraMask      syscall.RawSockaddrInet4
}

type in6AliasReq struct {
	IfraName       [syscall.IFNAMSIZ]byte
	IfraAddr       syscall.RawSockaddrInet6
	IfraDstAddr    syscall.RawSockaddrInet6
	IfraPrefixMask syscall.RawSockaddrInet6
	IfraFlags      int32
	IfraLifetime   in6AddrLifetime
}

type in6AddrLifetime struct {
	Ia6tExpire    float64
	Ia6tPreferred float64
	Ia6tVltime    uint32
	Ia6tPltime    uint32
}

const (
	darwin_SIOCAIFADDR_IN6       = 2155899162
	darwin_IN6_IFF_NODAD         = 0x0020
	darwin_IN6_IFF_SECURED       = 0x0400
	darwin_ND6_INFINITE_LIFETIME = 0xFFFFFFFF
)

func sockAddrInet4FromIP(ip net.IP) syscall.RawSockaddrInet4 {
	var rsa syscall.RawSockaddrInet4
	rsa.Len = uint8(unsafe.Sizeof(rsa))
	rsa.Family = syscall.AF_INET
	copy(rsa.Addr[:], ip.To4())
	return rsa
}

func sockAddrInet4FromMask(mask net.IPMask) syscall.RawSockaddrInet4 {
	var rsa syscall.RawSockaddrInet4
	rsa.Len = uint8(unsafe.Sizeof(rsa))
	rsa.Family = syscall.AF_INET
	copy(rsa.Addr[:], net.IP(mask).To4())
	return rsa
}

func sockAddrInet6FromIP(ip net.IP) syscall.RawSockaddrInet6 {
	var rsa syscall.RawSockaddrInet6
	rsa.Len = uint8(unsafe.Sizeof(rsa))
	rsa.Family = syscall.AF_INET6
	copy(rsa.Addr[:], ip.To16())
	return rsa
}

func sockAddrInet6FromMask(mask net.IPMask) syscall.RawSockaddrInet6 {
	var rsa syscall.RawSockaddrInet6
	rsa.Len = uint8(unsafe.Sizeof(rsa))
	rsa.Family = syscall.AF_INET6
	copy(rsa.Addr[:], net.IP(mask).To16())
	return rsa
}

func broadcastIPv4(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	mask4 := net.IP(mask).To4()
	if ip4 == nil || mask4 == nil {
		return net.IPv4zero
	}
	out := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		out[i] = ip4[i] | ^mask4[i]
	}
	return out
}
