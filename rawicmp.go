package icmp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/raw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"

	"golang.org/x/net/icmp"
)

// Handler maintains the underlying socket connection
type Handler struct {
	conn net.PacketConn

	// Log packets turn on logging if desirable
	Log bool
}

const (
	// Ethernet packet types - ETHER_TYPE
	ETH_P_IP    = 0x800  // IP
	ETH_P_8021Q = 0x8100 // VLAN

	// ICMP Packet types
	ICMPTypeEchoReply   = 0
	ICMPTypeEchoRequest = 8
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

	if p.EtherType() == ETH_P_IP {
		return p[14:]
	}
	// The IEEE 802.1Q tag, if present, then two EtherType contains the Tag Protocol Identifier (TPID) value of 0x8100
	// and true EtherType/Length is located after the Q-tag.
	// The TPID is followed by two octets containing the Tag Control Information (TCI) (the IEEE 802.1p priority (quality of service) and VLAN id).
	// also handle 802.1ad - 0x88a8
	if p.EtherType() == ETH_P_8021Q { // add 2 bytes to frame
		return p[16:]
	}
	if p.EtherType() == 0x88a8 { // add 6 bytes to frame
		return p[20:]
	}
	return p[14:]
}

// RawIPPacket provide access to IP fields without copying data.
// see: ipv4.ParseHeader in https://raw.githubusercontent.com/golang/net/master/ipv4/header.go
type RawIPPacket []byte

func (p RawIPPacket) IsValid() bool {
	if len(p) < 20 {
		return false
	}

	if len(p) < p.IHL() {
		return false
	}
	return true
}

func (p RawIPPacket) IHL() int        { return int(p[0]&0x0f) << 2 } // Internet header length
func (p RawIPPacket) Version() int    { return int(p[0] >> 4) }
func (p RawIPPacket) Protocol() int   { return int(p[9]) }
func (p RawIPPacket) TOS() int        { return int(p[1]) }
func (p RawIPPacket) ID() int         { return int(binary.BigEndian.Uint16(p[4:6])) }
func (p RawIPPacket) TTL() int        { return int(p[8]) }
func (p RawIPPacket) Checksum() int   { return int(binary.BigEndian.Uint16(p[10:12])) }
func (p RawIPPacket) Src() net.IP     { return net.IPv4(p[12], p[13], p[14], p[15]) }
func (p RawIPPacket) Dst() net.IP     { return net.IPv4(p[16], p[17], p[18], p[19]) }
func (p RawIPPacket) TotalLen() int   { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p RawIPPacket) Payload() []byte { return p[p.IHL():] }
func (p RawIPPacket) String() string {
	return fmt.Sprintf("version: %v src: %v dst: %v proto: %v ttl:%v tos: %v", p.Version(), p.Src(), p.Dst(), p.Protocol(), p.TTL(), p.TOS())
}

type RawICMPPacket []byte

func (p RawICMPPacket) Type() uint8          { return uint8(p[0]) }
func (p RawICMPPacket) Code() int            { return int(p[1]) }
func (p RawICMPPacket) Checksum() int        { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p RawICMPPacket) RestOfHeader() []byte { return p[4:8] }
func (p RawICMPPacket) EchoID() uint16       { return binary.BigEndian.Uint16(p[4:6]) }
func (p RawICMPPacket) EchoSeq() uint16      { return binary.BigEndian.Uint16(p[6:8]) }
func (p RawICMPPacket) EchoData() string     { return string(p[8:len(p)]) }
func (p RawICMPPacket) Payload() []byte      { return p[8:len(p)] }
func (p RawICMPPacket) String() string {
	switch p.Type() {
	case ICMPTypeEchoReply, ICMPTypeEchoRequest:
		return fmt.Sprintf("icmp echo code: %v id: %v data: %v", p.EchoID(), p.Code(), string(p.EchoData()))
	}
	return fmt.Sprintf("icmp type %v code: %v data: %X", p.Type(), p.Code(), p.Payload())
}

func (h *Handler) sendRawICMP(src net.IP, dst net.IP, p RawICMPPacket) error {

	// TODO: reuse h.conn and write directly to socket
	c, err := net.ListenPacket("ip4:1", "0.0.0.0") // ICMP for IPv4
	if err != nil {
		log.Error("error in listen packet: ", err)
		return err
	}
	defer c.Close()

	r, err := ipv4.NewRawConn(c)
	if err != nil {
		log.Error("error in newrawconn: ", err)
		return err
	}

	iph := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0xc0, // DSCP CS6
		TotalLen: ipv4.HeaderLen + len(p),
		TTL:      10,
		Protocol: 1,
		Src:      src,
		Dst:      dst,
	}

	if h.Log {
		log.Infof("send %v from %v to %v", p, src, dst)
	}
	if err := r.WriteTo(iph, p, nil); err != nil {
		log.Error("failed to write ", err)
		return err
	}

	return nil
}

// New start the ICMP listening service for the nic and return a handle
// to access ICMP functionality.
func New(nic string) (h *Handler, err error) {
	h = &Handler{}
	ifi, err := net.InterfaceByName(nic)
	if err != nil {
		log.WithFields(log.Fields{"nic": nic}).Errorf("NIC cannot open nic %s error %s ", nic, err)
		return nil, err
	}

	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Load EtherType value from Ethernet header
		bpf.LoadAbsolute{
			Off:  14 + 9, // IP Protocol field - 14 Eth bytes + 9 IP header
			Size: 1,
		},
		// If IP Protocol is equal ICMP, jump to allow
		// packet to be accepted
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      1, // ICMP protocol
			SkipTrue: 1,
		},
		// not ICMP
		bpf.RetConstant{
			Val: 0,
		},
		// IP Protocl matches ICMP, accept up to 1500
		// bytes of packet
		bpf.RetConstant{
			Val: 1500,
		},
	})

	h.conn, err = raw.ListenPacket(ifi, ETH_P_IP, &raw.Config{Filter: bpf})
	if err != nil {
		log.Error("icmp raw.ListenAndServe failed ", err)
		return nil, err
	}

	go h.readLoop(ifi.MTU)

	return h, nil
}

// Close the underlaying socket
func (h *Handler) Close() { h.conn.Close() }

func (h *Handler) readLoop(bufSize int) {
	defer h.conn.Close()

	buf := make([]byte, bufSize)
	for {
		if err := h.conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			log.Error("icmp failed to set timeout ", err)
			return
		}

		n, _, err := h.conn.ReadFrom(buf)
		if err != nil {
			icmpTable.cond.Broadcast() // wakeup all goroutines
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				// log.Info("ARP read error is temporary - retry", err1)
				continue
			}
			log.Error("icmp conn.ReadFrom error ", err)
			return
		}

		ether := RawEthPacket(buf[:n])
		if ether.EtherType() != ETH_P_IP || !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}

		ipFrame := RawIPPacket(ether.Payload())
		if !ipFrame.IsValid() {
			log.Error("icmp invalid ip packet ", ether.EtherType())
			continue
		}

		// only interested in ICMP packets; wwithout BPF we also receive UDP and TCP packets
		if ipFrame.Protocol() != 1 { // ICMPv4 = 1
			log.Error("icmp ignore protocol ", ipFrame)
			continue
		}

		icmpFrame := RawICMPPacket(ipFrame.Payload())

		switch icmpFrame.Type() {
		case ICMPTypeEchoReply:
			if h.Log {
				log.Infof("rcvd %+v", icmpFrame)
			}
			icmpTable.cond.L.Lock()
			if len(icmpTable.table) <= 0 {
				icmpTable.cond.L.Unlock()
				// log.Info("no waiting")
				continue
			}
			icmpTable.cond.L.Unlock()

			// parse message - create a copy
			icmpMsg, err := icmp.ParseMessage(1, ipFrame.Payload())
			if err != nil {
				log.Error("icmp invalid icmp packet ", err)
				continue
			}

			icmpTable.cond.L.Lock()
			entry, ok := icmpTable.table[icmpFrame.EchoID()]
			if ok {
				entry.msgRecv = icmpMsg
				// log.Info("wakingup", icmpFrame.EchoID)
			}
			icmpTable.cond.L.Unlock()
			icmpTable.cond.Broadcast()

		default:
			if h.Log {
				log.Infof("unimplemented rcvd %+v", icmpFrame)
			}
		}
	}
}
