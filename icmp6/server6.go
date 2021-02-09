package icmp6

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/irai/icmp/packet"
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
	ifi          *net.Interface
	notification chan<- Event
	Router       Router
	LANRouters   map[string]*Router
	LANHosts     map[string]*Host
	Config       Config
}

// Config define server configuration values
type Config struct {
	EnableRADVServer bool
}

// New creates an ICMPv6 handler with default values
func New(nic string) (*Handler, error) {
	return Config{}.New(nic)
}

// New creates an ICMPv6 handler with config values
func (config Config) New(nic string) (*Handler, error) {
	var err error

	h := &Handler{Config: config, LANRouters: make(map[string]*Router), LANHosts: make(map[string]*Host)}
	h.ifi, err = net.InterfaceByName(nic)
	if err != nil {
		return nil, fmt.Errorf("interface not found nic=%s: %w", nic, err)
	}

	c, err := net.ListenPacket("ip6:1", "::") // ICMP for IPv6
	if err != nil {
		return nil, fmt.Errorf("error in ListenPacket: %w", err)
	}

	h.pc = ipv6.NewPacketConn(c)

	return h, nil
}

// Close closes the underlying sockets
func (h *Handler) Close() error {
	if h.pc != nil {
		return h.pc.Close()
	}
	return nil
}

// AddNotificationChannel set the notification channel for ICMP6 messages
func (h *Handler) AddNotificationChannel(notification chan<- Event) {
	h.notification = notification
}

func (h *Handler) autoConfigureRouter(router Router) {
	if len(h.Router.Prefixes) == 0 {
		h.Router = router

	}
}

var repeat int

func (h *Handler) processPacket(ether packet.Ether) error {

	ip6Frame := packet.IP6(ether.Payload())
	if !ip6Frame.IsValid() {
		return fmt.Errorf("invalid ip6 packet type: %s", ether)
	}
	fmt.Println("ether: ", ether)
	fmt.Println("ip   : ", ip6Frame)

	if len(ip6Frame.Payload()) < icmpLen {
		return fmt.Errorf("ICMPv6 message too short: %w", errParseMessage)
	}

	// TODO: verify checksum?

	h.mutex.Lock()
	defer h.mutex.Unlock()

	var found bool
	var host *Host
	t := ipv6.ICMPType(ip6Frame.Payload()[0])
	switch t {
	case ipv6.ICMPTypeNeighborAdvertisement:
		msg := new(NeighborAdvertisement)
		if err := msg.unmarshal(ip6Frame.Payload()[icmpLen:]); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6 neighbor advertisement: %+v\n", msg)
		host, found = h.findOrCreateHost(ether.Src(), msg.TargetAddress)
		host.LastSeen = time.Now()
		host.Online = true

	case ipv6.ICMPTypeNeighborSolicitation:
		msg := new(NeighborSolicitation)
		if err := msg.unmarshal(ip6Frame.Payload()[icmpLen:]); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6 neighbor solicitation: %+v\n", msg)
		host, found = h.findOrCreateHost(ether.Src(), msg.TargetAddress)
		host.LastSeen = time.Now()
		host.Online = true

	case ipv6.ICMPTypeRouterAdvertisement:
		msg := new(RouterAdvertisement)
		if err := msg.unmarshal(ip6Frame.Payload()[icmpLen:]); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		if repeat%16 != 0 {
			fmt.Printf("icmp6 repeated router advertisement : \n")
			repeat++
			break
		}
		repeat++
		fmt.Printf("icmp6 router advertisement : %+v\n", msg)
		host, found = h.findOrCreateHost(ether.Src(), ip6Frame.Src())
		host.Router = true
		router, _ := h.findOrCreateRouter(ether.Src(), ip6Frame.Src())
		router.ManagedFlag = msg.ManagedConfiguration
		router.CurHopLimit = msg.CurrentHopLimit
		router.DefaultLifetime = msg.RouterLifetime
		router.Options = msg.Options

		prefixes := []PrefixInformation{}
		for _, v := range msg.Options {
			switch v.Code() {
			case optMTU:
				o := v.(*MTU)
				fmt.Println(" options mtu ", v.Code(), o)
				router.MTU = uint32(*o)
			case optPrefixInformation:
				o := v.(*PrefixInformation)
				fmt.Println(" options prefix ", v.Code(), o)
				prefixes = append(prefixes, *o)
			case optRDNSS:
				o := v.(*RecursiveDNSServer)
				fmt.Println(" options RDNSS ", v.Code(), o)
				router.RDNSS = o
			case optSourceLLA:
				o := v.(*LinkLayerAddress)
				fmt.Println(" options LLA ", v.Code(), o)
				if !bytes.Equal(o.Addr, ether.Src()) {
					log.Printf("error: icmp6 unexpected sourceLLA=%s etherFrame=%s", o.Addr, ether.Src())
				}
			}
		}

		if len(prefixes) > 0 {
			router.Prefixes = prefixes
			if len(prefixes) > 1 {
				fmt.Printf("error: icmp6 invalid prefix list len=%d list=%v", len(prefixes), prefixes)
			}

			h.autoConfigureRouter(*router)
		}

	case ipv6.ICMPTypeRouterSolicitation:
		msg := new(RouterSolicitation)
		if err := msg.unmarshal(ip6Frame.Payload()[icmpLen:]); err != nil {
			return fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
		}
		fmt.Printf("icmp6 router solicitation: %+v\n", msg)
		host, found = h.findOrCreateHost(ether.Src(), ip6Frame.Src())
	case ipv6.ICMPTypeEchoReply:
		fmt.Printf("icmp6 echo reply: %s \n", ip6Frame)
		msg := packet.ICMPEcho(ip6Frame.Payload())
		if !msg.IsValid() {
			return fmt.Errorf("invalid icmp echo msg len=%d", len(ip6Frame.Payload()))
		}
		fmt.Printf("icmp6 echo msg: %s\n", msg)
		host, found = h.findOrCreateHost(ether.Src(), ip6Frame.Src())
	case ipv6.ICMPTypeEchoRequest:
		fmt.Printf("icmp6 echo request %s \n", ip6Frame)
	default:
		log.Printf("icmp6 not implemented type=%v ip6=%s\n", t, ip6Frame)
		return fmt.Errorf("ndp: unrecognized ICMPv6 type %d: %w", t, errParseMessage)
	}

	if host != nil {
		host.LastSeen = time.Now()
		host.Online = true
	}
	if !found && h.notification != nil {
		go func() { h.notification <- Event{Type: t, Host: *host} }()
	}

	return nil
}

// ListenAndServe listend for raw ICMP6 packets and process packets
func (h *Handler) ListenAndServe(ctxt context.Context) (err error) {

	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: packet.EthType8021Q, SkipFalse: 1}, // EtherType is 2 pushed out by two bytes
		bpf.LoadAbsolute{Off: 14, Size: 2},
		// IPv6 && ICMPv6?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: packet.EthTypeIP6, SkipFalse: 3},
		bpf.LoadAbsolute{Off: 14 + 6, Size: 1},                 // IPv6 Protocol field - 14 Eth bytes + 6 IPv6 header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipFalse: 1}, // ICMPv6 protocol - 58
		bpf.RetConstant{Val: 1540},                             // matches ICMPv6, accept up to 1540 (1500 payload + ether header)
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		log.Fatal("bpf assemble error", err)
	}

	h.conn, err = raw.ListenPacket(h.ifi, packet.EthTypeIP6, &raw.Config{Filter: bpf})
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

		ether := packet.Ether(buf[:n])
		if ether.EtherType() != packet.EthTypeIP6 || !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}

		fmt.Println("icmp: got ipv6 packet type=", ether.EtherType())
		if err := h.processPacket(ether); err != nil {
			fmt.Printf("icmp6 error processing packet: %s", err)
		}
	}
}
