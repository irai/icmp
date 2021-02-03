package icmp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/irai/icmp/icmp6"
	"github.com/irai/icmp/packet"
	"github.com/mdlayher/raw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"

	"golang.org/x/net/icmp"
)

// LogAll packets turn on logging if desirable
var LogAll bool

// Handler maintains the underlying socket connection
type Handler struct {
	ifi   *net.Interface
	conn  net.PacketConn
	conn6 net.PacketConn
}

func (h *Handler) sendRawICMP(src net.IP, dst net.IP, p packet.ICMP4) error {

	// TODO: reuse h.conn and write directly to socket
	c, err := net.ListenPacket("ip4:1", "0.0.0.0") // ICMP for IPv4
	if err != nil {
		log.Error("icmp error in listen packet: ", err)
		return err
	}
	defer c.Close()

	r, err := ipv4.NewRawConn(c)
	if err != nil {
		log.Error("icmp error in newrawconn: ", err)
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

	if LogAll {
		log.WithFields(log.Fields{"group": "icmp", "src": src, "dst": dst}).Debugf("icmp send msg type=%v", p.Type())
	}
	if err := r.WriteTo(iph, p, nil); err != nil {
		log.Error("icmp failed to write ", err)
		return err
	}

	return nil
}

// New returns an ICMPv4 handler
func New(nic string) (h *Handler, err error) {
	h = &Handler{}
	h.ifi, err = net.InterfaceByName(nic)
	if err != nil {
		return nil, fmt.Errorf("interface not found nic=%s err=%w", nic, err)
	}

	return h, nil
}

// Close the underlaying socket
func (h *Handler) Close() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}

func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	/*****
	bpf2, err := bpf.Assemble([]bpf.Instruction{
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
	****/

	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: packet.ETH_P_8021Q, SkipFalse: 1}, // EtherType is 2 pushed out by two bytes
		bpf.LoadAbsolute{Off: 14, Size: 2},
		// IPv4 && ICMPv4?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: packet.ETH_P_IP, SkipFalse: 4},
		bpf.LoadAbsolute{Off: 14 + 9, Size: 1},                // IPv4 Protocol field - 14 Eth bytes + 9 IPv4 header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipFalse: 1}, // ICMPv4 protocol - 1
		bpf.RetConstant{Val: 1540},                            // matches ICMPv4, accept up to 1540 (1500 payload + ether header)
		bpf.RetConstant{Val: 0},
		// IPv6 && ICMPv6?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: packet.ETH_P_IP6, SkipFalse: 3},
		bpf.LoadAbsolute{Off: 14 + 6, Size: 1},                 // IPv6 Protocol field - 14 Eth bytes + 6 IPv6 header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipFalse: 1}, // ICMPv6 protocol - 58
		bpf.RetConstant{Val: 1540},                             // matches ICMPv6, accept up to 1540 (1500 payload + ether header)
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		log.Fatal("bpf assemble error", err)
	}

	h.conn, err = raw.ListenPacket(h.ifi, packet.ETH_P_IP, &raw.Config{Filter: bpf})
	if err != nil {
		h.conn = nil // on windows, not impleted returns a partially completed conn
		return fmt.Errorf("raw.ListenPacket error: %w", err)
	}
	defer h.conn.Close()

	buf := make([]byte, h.ifi.MTU)
	for {
		if err = h.conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			if ctxt.Err() != context.Canceled {
				return fmt.Errorf("setReadDeadline error: %w", err)
			}
			return
		}

		n, _, err1 := h.conn.ReadFrom(buf)
		if err1 != nil {
			if err1, ok := err1.(net.Error); ok && err1.Temporary() {
				continue
			}
			icmpTable.cond.Broadcast() // wakeup all goroutines
			if ctxt.Err() != context.Canceled {
				return fmt.Errorf("read error: %w", err1)
			}
			return
		}

		ether := packet.RawEthPacket(buf[:n])
		if (ether.EtherType() != packet.ETH_P_IP && ether.EtherType() != packet.ETH_P_IP6) || !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}

		if ether.EtherType() == packet.ETH_P_IP6 {
			fmt.Println("icmp: got ipv6 packet")
			icmp6.Process(buf)
			continue
		}

		ipFrame := packet.IP4(ether.Payload())
		if !ipFrame.IsValid() {
			log.Error("icmp invalid ip packet ", ether.EtherType())
			continue
		}

		// only interested in ICMP packets; wwithout BPF we also receive UDP and TCP packets
		if ipFrame.Protocol() != 1 { // ICMPv4 = 1
			log.Error("icmp ignore protocol ", ipFrame)
			continue
		}

		icmpFrame := packet.ICMP4(ipFrame.Payload())

		switch icmpFrame.Type() {
		case packet.ICMPTypeEchoReply:
			if LogAll {
				log.WithFields(log.Fields{"group": "icmp"}).Debugf("rcvd icmp %+v ", icmpFrame)
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

		case packet.ICMPTypeEchoRequest:
			if LogAll {
				log.WithFields(log.Fields{"group": "icmp", "type": icmpFrame.Type(), "code": icmpFrame.Code()}).Debugf("rcvd unimplemented icmp packet % X ", icmpFrame.Payload())
			}

		default:
			log.WithFields(log.Fields{"group": "icmp", "type": icmpFrame.Type(), "code": icmpFrame.Code(), "fromIP": ipFrame.Src(), "toIP": ipFrame.Dst()}).Warnf("rcvd unimplemented icmp packet")
			if LogAll {
				log.WithFields(log.Fields{"group": "icmp", "type": icmpFrame.Type(), "code": icmpFrame.Code()}).Debugf("rcvd unimplemented icmp packet % X", icmpFrame.Payload())
			}
		}
	}
}
