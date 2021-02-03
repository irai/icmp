package icmp6

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/irai/icmp/packet"
	"github.com/mdlayher/netx/rfc4193"
	"github.com/mdlayher/raw"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv6"
)

// LogAll packets turn on logging if desirable
var LogAll bool

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	pc           *ipv6.PacketConn
	conn         *raw.Conn
	mutex        sync.Mutex
	prefixes     []net.IPNet
	ifi          *net.Interface
	notification chan<- Message
}

var ipv6LinkLocal = func(cidr string) *net.IPNet {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return net
}("fe80::/10")

// GenerateULA creates a universal local address
// Usefule to create a IPv6 prefix when there is no global IPv6 routing
func GenerateULA(mac net.HardwareAddr, subnet uint16) (*net.IPNet, error) {
	prefix, err := rfc4193.Generate(mac)
	if err != nil {
		return nil, err
	}
	return prefix.Subnet(subnet).IPNet(), nil
}

// New returns an ICMPv6 handler
func New(nic string) (*Handler, error) {
	var err error

	h := &Handler{}
	h.ifi, err = net.InterfaceByName(nic)
	if err != nil {
		return nil, fmt.Errorf("interface not found nic=%s err=%w", nic, err)
	}
	return h, nil
}

func (s *Handler) Close() error {
	if s.pc != nil {
		return s.pc.Close()
	}
	return nil
}

// AddNotificationChannel set the notification channel for ICMP6 messages
func (s *Handler) AddNotificationChannel(notification chan<- Message) {
	s.notification = notification
}

func Process(ether packet.RawEthPacket) error {

	ip6Frame := packet.IP6(ether.Payload())
	if !ip6Frame.IsValid() {
		return fmt.Errorf("invalid icmp packet type: %s", ether.EtherType())
	}

	// TODO: This will parse and create a struct; should optimise this to use references to buffer
	msg, err := ParseMessage(ip6Frame.Payload())
	if err != nil {
		fmt.Printf("msg=[% x]\n", ip6Frame.Payload())
		return err
	}

	switch msg.Type() {

	case ipv6.ICMPTypeRouterSolicitation:
		fmt.Printf("icmp6 router solicitation: %+v\n", msg)
		/**
		if err := s.RouterAdvertisement(addr); err != nil {
			fmt.Printf("error in icmp6 router solicitation: %s", err)
			return err
		}
		**/

	case ipv6.ICMPTypeRouterAdvertisement:
		fmt.Printf("icmp6 router advertisement: %+v\n", msg)

	case ipv6.ICMPTypeNeighborAdvertisement:
		fmt.Printf("icmp6 neighbor advertisement: %+v\n", msg)

	case ipv6.ICMPTypeNeighborSolicitation:
		fmt.Printf("icmp6 neighbor solicitation: %+v\n", msg)
		// m = new(NeighborSolicitation)

	default:
		log.Printf("icmp6 not implemented msg=%+v\n", msg)
	}
	return nil
}

/****
func (s *Handler) ListenAndServe(ctxt context.Context) error {
	// TODO(correctness): would it be better to listen on
	// net.IPv6linklocalallrouters? Just specifying that results in an error,
	// though.
	conn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{IP: net.IPv6unspecified, Zone: ""})
	if err != nil {
		return err
	}

	s.pc = ipv6.NewPacketConn(conn)
	s.pc.SetHopLimit(255)          // as per RFC 4861, section 4.1
	s.pc.SetMulticastHopLimit(255) // as per RFC 4861, section 4.1

	var filter ipv6.ICMPFilter
	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeRouterSolicitation)
	if err := s.pc.SetICMPFilter(&filter); err != nil {
		return err
	}

	go func() {
		for {
			s.RouterAdvertisement(nil) // TODO: handle error
			time.Sleep(1 * time.Minute)
		}
	}()

	buf := make([]byte, s.ifi.MTU)
	for {
		n, _, _, err := s.pc.ReadFrom(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			if ctxt.Err() == context.Canceled {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
	}
}
***/

func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: packet.ETH_P_8021Q, SkipFalse: 1}, // EtherType is 2 pushed out by two bytes
		bpf.LoadAbsolute{Off: 14, Size: 2},
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

	h.conn, err = raw.ListenPacket(h.ifi, packet.ETH_P_IP6, &raw.Config{Filter: bpf})
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

		fmt.Println("icmp: got ipv6 packet")
		Process(ether)
	}
}
