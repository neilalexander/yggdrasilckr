package ckriprwc

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestBuildOversizeResponseIPv6(t *testing.T) {
	orig := make([]byte, 80)
	orig[0] = 0x60
	copy(orig[8:24], net.ParseIP("2001:db8::1").To16())
	copy(orig[24:40], net.ParseIP("2001:db8::2").To16())
	copy(orig[40:], []byte("payload"))

	packet, ok := buildOversizeResponse(orig, 1280)
	if !ok {
		t.Fatal("expected IPv6 PTB response")
	}

	hdr, err := ipv6.ParseHeader(packet)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got, want := hdr.Src.String(), net.ParseIP("2001:db8::2").String(); got != want {
		t.Fatalf("src = %s, want %s", got, want)
	}
	if got, want := hdr.Dst.String(), net.ParseIP("2001:db8::1").String(); got != want {
		t.Fatalf("dst = %s, want %s", got, want)
	}

	msg, err := icmp.ParseMessage(58, packet[ipv6.HeaderLen:])
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if got, want := msg.Type, ipv6.ICMPTypePacketTooBig; got != want {
		t.Fatalf("type = %v, want %v", got, want)
	}
	if got, want := msg.Code, 0; got != want {
		t.Fatalf("code = %d, want %d", got, want)
	}
	body, ok := msg.Body.(*icmp.PacketTooBig)
	if !ok {
		t.Fatalf("body type = %T, want *icmp.PacketTooBig", msg.Body)
	}
	if got, want := body.MTU, 1280; got != want {
		t.Fatalf("mtu = %d, want %d", got, want)
	}
	if !bytes.Equal(body.Data, orig) {
		t.Fatalf("data mismatch")
	}
}

func TestBuildOversizeResponseIPv4(t *testing.T) {
	orig := make([]byte, 64)
	orig[0] = 0x45
	orig[6] = 0x40 // DF
	copy(orig[12:16], net.ParseIP("192.0.2.10").To4())
	copy(orig[16:20], net.ParseIP("198.51.100.20").To4())
	copy(orig[20:], []byte("payload"))

	packet, ok := buildOversizeResponse(orig, 1400)
	if !ok {
		t.Fatal("expected IPv4 fragmentation-needed response")
	}

	hdr, err := ipv4.ParseHeader(packet)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got, want := hdr.Src.String(), net.ParseIP("198.51.100.20").String(); got != want {
		t.Fatalf("src = %s, want %s", got, want)
	}
	if got, want := hdr.Dst.String(), net.ParseIP("192.0.2.10").String(); got != want {
		t.Fatalf("dst = %s, want %s", got, want)
	}
	if got, want := hdr.Protocol, 1; got != want {
		t.Fatalf("protocol = %d, want %d", got, want)
	}

	icmpPart := packet[ipv4.HeaderLen:]
	if got, want := icmpPart[0], byte(ipv4.ICMPTypeDestinationUnreachable); got != want {
		t.Fatalf("icmp type = %d, want %d", got, want)
	}
	if got, want := icmpPart[1], byte(4); got != want {
		t.Fatalf("icmp code = %d, want %d", got, want)
	}
	if got := binary.BigEndian.Uint16(icmpPart[4:6]); got != 0 {
		t.Fatalf("unused field = %d, want 0", got)
	}
	if got, want := binary.BigEndian.Uint16(icmpPart[6:8]), uint16(1400); got != want {
		t.Fatalf("next-hop mtu = %d, want %d", got, want)
	}

	msg, err := icmp.ParseMessage(1, icmpPart)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if got, want := msg.Type, ipv4.ICMPTypeDestinationUnreachable; got != want {
		t.Fatalf("type = %v, want %v", got, want)
	}
	if got, want := msg.Code, 4; got != want {
		t.Fatalf("code = %d, want %d", got, want)
	}
	body, ok := msg.Body.(*icmp.DstUnreach)
	if !ok {
		t.Fatalf("body type = %T, want *icmp.DstUnreach", msg.Body)
	}
	if !bytes.Equal(body.Data, orig) {
		t.Fatalf("data mismatch")
	}
}

func TestBuildOversizeResponseIPv4WithoutDF(t *testing.T) {
	orig := make([]byte, 64)
	orig[0] = 0x45
	copy(orig[12:16], net.ParseIP("192.0.2.10").To4())
	copy(orig[16:20], net.ParseIP("198.51.100.20").To4())

	if packet, ok := buildOversizeResponse(orig, 20); ok || packet != nil {
		t.Fatal("expected no response without DF")
	}
}

func TestBuildDestinationUnreachableResponseIPv6(t *testing.T) {
	orig := make([]byte, 80)
	orig[0] = 0x60
	copy(orig[8:24], net.ParseIP("2001:db8::1").To16())
	copy(orig[24:40], net.ParseIP("2001:db8::2").To16())

	packet, ok := buildDestinationUnreachableResponse(
		orig,
		net.ParseIP("2001:db8::2"),
		net.ParseIP("2001:db8::1"),
		1,
	)
	if !ok {
		t.Fatal("expected IPv6 destination unreachable response")
	}

	hdr, err := ipv6.ParseHeader(packet)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got, want := hdr.Src.String(), net.ParseIP("2001:db8::2").String(); got != want {
		t.Fatalf("src = %s, want %s", got, want)
	}
	if got, want := hdr.Dst.String(), net.ParseIP("2001:db8::1").String(); got != want {
		t.Fatalf("dst = %s, want %s", got, want)
	}

	msg, err := icmp.ParseMessage(58, packet[ipv6.HeaderLen:])
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if got, want := msg.Type, ipv6.ICMPTypeDestinationUnreachable; got != want {
		t.Fatalf("type = %v, want %v", got, want)
	}
	if got, want := msg.Code, 1; got != want {
		t.Fatalf("code = %d, want %d", got, want)
	}
	body, ok := msg.Body.(*icmp.DstUnreach)
	if !ok {
		t.Fatalf("body type = %T, want *icmp.DstUnreach", msg.Body)
	}
	if !bytes.Equal(body.Data, orig) {
		t.Fatalf("data mismatch")
	}
}

func TestBuildDestinationUnreachableResponseIPv4(t *testing.T) {
	orig := make([]byte, 64)
	orig[0] = 0x45
	copy(orig[12:16], net.ParseIP("192.0.2.10").To4())
	copy(orig[16:20], net.ParseIP("198.51.100.20").To4())

	packet, ok := buildDestinationUnreachableResponse(
		orig,
		net.IPv4(0, 0, 0, 0),
		net.ParseIP("192.0.2.10").To4(),
		13,
	)
	if !ok {
		t.Fatal("expected IPv4 destination unreachable response")
	}

	hdr, err := ipv4.ParseHeader(packet)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got, want := hdr.Src.String(), "0.0.0.0"; got != want {
		t.Fatalf("src = %s, want %s", got, want)
	}
	if got, want := hdr.Dst.String(), net.ParseIP("192.0.2.10").String(); got != want {
		t.Fatalf("dst = %s, want %s", got, want)
	}

	msg, err := icmp.ParseMessage(1, packet[ipv4.HeaderLen:])
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if got, want := msg.Type, ipv4.ICMPTypeDestinationUnreachable; got != want {
		t.Fatalf("type = %v, want %v", got, want)
	}
	if got, want := msg.Code, 13; got != want {
		t.Fatalf("code = %d, want %d", got, want)
	}
	body, ok := msg.Body.(*icmp.DstUnreach)
	if !ok {
		t.Fatalf("body type = %T, want *icmp.DstUnreach", msg.Body)
	}
	if !bytes.Equal(body.Data, orig) {
		t.Fatalf("data mismatch")
	}
}
