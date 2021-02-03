package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Ethernet packet types - ETHER_TYPE
const (
	EthTypeIP4    = 0x800  // IPv4
	EthTypeIP6    = 0x86DD // IPv6
	EthTypeARP    = 0x0806 // ARP
	EthType8021Q  = 0x8100 // VLAN 802.1Q
	EthType8021AD = 0x88a8 // VLAN 802.1ad

	// ICMP Packet types
	ICMPTypeEchoReply   = 0
	ICMPTypeEchoRequest = 8

	IP6HeaderLen = 40 // IP6 header len
)

// RawEthPacket provide access to ethernet fields without copying the structure
// see: https://medium.com/@mdlayher/network-protocol-breakdown-ethernet-and-go-de985d726cc1
type RawEthPacket []byte

func (p RawEthPacket) IsValid() bool {
	// Minimum len to contain two hardware address and EtherType (2 bytes)
	if len(p) < 14 {
		return false
	}
	return true
}

func (p RawEthPacket) EtherType() uint16 { return binary.BigEndian.Uint16(p[12:14]) }
func (p RawEthPacket) Payload() []byte {

	if p.EtherType() == EthTypeIP4 || p.EtherType() == EthTypeIP6 {
		return p[14:]
	}
	// The IEEE 802.1Q tag, if present, then two EtherType contains the Tag Protocol Identifier (TPID) value of 0x8100
	// and true EtherType/Length is located after the Q-tag.
	// The TPID is followed by two octets containing the Tag Control Information (TCI) (the IEEE 802.1p priority (quality of service) and VLAN id).
	// also handle 802.1ad - 0x88a8
	if p.EtherType() == EthType8021Q { // add 2 bytes to frame
		return p[16:]
	}

	if p.EtherType() == EthType8021AD { // add 6 bytes to frame
		return p[20:]
	}
	return p[14:]
}
func (p RawEthPacket) Dst() net.HardwareAddr { return net.HardwareAddr(p[8 : 8+6]) }
func (p RawEthPacket) Src() net.HardwareAddr { return net.HardwareAddr(p[14 : 14+6]) }
func (p RawEthPacket) String() string {
	return fmt.Sprintf("type: %x src: %v dst: %v len: %v", p.EtherType(), p.Src(), p.Dst(), len(p))
}

// IP4 provide access to IP fields without copying data.
// see: ipv4.ParseHeader in https://raw.githubusercontent.com/golang/net/master/ipv4/header.go
type IP4 []byte

func (p IP4) IsValid() bool {
	if len(p) < 20 {
		return false
	}

	if len(p) < p.IHL() {
		return false
	}
	return true
}

func (p IP4) IHL() int        { return int(p[0]&0x0f) << 2 } // Internet header length
func (p IP4) Version() int    { return int(p[0] >> 4) }
func (p IP4) Protocol() int   { return int(p[9]) }
func (p IP4) TOS() int        { return int(p[1]) }
func (p IP4) ID() int         { return int(binary.BigEndian.Uint16(p[4:6])) }
func (p IP4) TTL() int        { return int(p[8]) }
func (p IP4) Checksum() int   { return int(binary.BigEndian.Uint16(p[10:12])) }
func (p IP4) Src() net.IP     { return net.IPv4(p[12], p[13], p[14], p[15]) }
func (p IP4) Dst() net.IP     { return net.IPv4(p[16], p[17], p[18], p[19]) }
func (p IP4) TotalLen() int   { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p IP4) Payload() []byte { return p[p.IHL():] }
func (p IP4) String() string {
	return fmt.Sprintf("version: %v src: %v dst: %v proto: %v ttl:%v tos: %v", p.Version(), p.Src(), p.Dst(), p.Protocol(), p.TTL(), p.TOS())
}

type ICMP4 []byte

func (p ICMP4) Type() uint8          { return uint8(p[0]) }
func (p ICMP4) Code() int            { return int(p[1]) }
func (p ICMP4) Checksum() int        { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP4) RestOfHeader() []byte { return p[4:8] }
func (p ICMP4) EchoID() uint16       { return binary.BigEndian.Uint16(p[4:6]) }
func (p ICMP4) EchoSeq() uint16      { return binary.BigEndian.Uint16(p[6:8]) }
func (p ICMP4) EchoData() string     { return string(p[8:]) }
func (p ICMP4) Payload() []byte      { return p[8:] }
func (p ICMP4) String() string {

	switch p.Type() {
	case ICMPTypeEchoReply:
		return fmt.Sprintf("echo reply code: %v id: %v data: %v", p.EchoID(), p.Code(), string(p.EchoData()))
	case ICMPTypeEchoRequest:
		return fmt.Sprintf("echo request code: %v id: %v data: %v", p.EchoID(), p.Code(), string(p.EchoData()))
	}
	return fmt.Sprintf("type %v code: %v", p.Type(), p.Code())
}

// IP6 structure: see https://github.com/golang/net/blob/master/ipv6/header.go
type IP6 []byte

func (p IP6) IsValid() bool {
	if len(p) >= IP6HeaderLen && p.PayloadLen()+IP6HeaderLen == len(p) {
		return true
	}
	fmt.Println("warning payload differ ", len(p), p.PayloadLen()+IP6HeaderLen)
	return false
}

func (p IP6) Version() int      { return int(p[0]) >> 4 }                                // protocol version
func (p IP6) TrafficClass() int { return int(p[0]&0x0f)<<4 | int(p[1])>>4 }              // traffic class
func (p IP6) FlowLabel() int    { return int(p[1]&0x0f)<<16 | int(p[2])<<8 | int(p[3]) } // flow label
func (p IP6) PayloadLen() int   { return int(binary.BigEndian.Uint16(p[4:6])) }          // payload length
func (p IP6) NextHeader() int   { return int(p[6]) }                                     // next header
func (p IP6) HopLimit() int     { return int(p[7]) }                                     // hop limit
func (p IP6) Src() net.IP       { return net.IP(p[8:24]) }                               // source address
func (p IP6) Dst() net.IP       { return net.IP(p[24:40]) }                              // destination address
func (p IP6) Payload() []byte   { return p[40:] }
func (p IP6) String() string {
	return fmt.Sprintf("version: %v src: %v dst: %v nextHeader: %v hoplimit:%v class: %v", p.Version(), p.Src(), p.Dst(), p.NextHeader(), p.HopLimit(), p.TrafficClass())
}
