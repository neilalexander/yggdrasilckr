package ckriprwc

import (
	"encoding/binary"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	icmpv4CodeNetworkUnreachable           = 0
	icmpv4CodeFragmentationNeededAndDFSet  = 4
	icmpv4CodeCommunicationAdminProhibited = 13
)

func internetChecksum(b []byte) uint16 {
	csumcv := len(b) - 1
	sum := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		sum += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		sum += uint32(b[csumcv])
	}
	sum = sum>>16 + sum&0xffff
	sum = sum + sum>>16
	return ^uint16(sum)
}

func ipv4Header_Marshal(h *ipv4.Header) ([]byte, error) {
	b, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(b[10:12], 0)
	binary.BigEndian.PutUint16(b[10:12], internetChecksum(b))
	return b, nil
}

func CreateICMPv4(dst net.IP, src net.IP, mtype ipv4.ICMPType, mcode int, mbody icmp.MessageBody) ([]byte, error) {
	icmpMessage := icmp.Message{
		Type: mtype,
		Code: mcode,
		Body: mbody,
	}

	icmpMessageBuf, err := icmpMessage.Marshal(nil)
	if err != nil {
		return nil, err
	}

	ipv4Header := ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(icmpMessageBuf),
		TTL:      255,
		Protocol: 1,
		Src:      src,
		Dst:      dst,
	}

	ipv4HeaderBuf, err := ipv4Header_Marshal(&ipv4Header)
	if err != nil {
		return nil, err
	}

	responsePacket := make([]byte, ipv4Header.TotalLen)
	copy(responsePacket[:ipv4.HeaderLen], ipv4HeaderBuf)
	copy(responsePacket[ipv4.HeaderLen:], icmpMessageBuf)
	return responsePacket, nil
}
