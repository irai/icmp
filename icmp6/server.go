package icmp6

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/mdlayher/netx/rfc4193"

	"golang.org/x/net/ipv6"
)

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	pc           *ipv6.PacketConn
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

func Process(buf []byte) error {

	// This will parse and create a struct; should optimise this to use references to buffer
	msg, err := ParseMessage(buf)
	if err != nil {
		fmt.Printf("msg=[% x]\n", buf)
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
		fmt.Printf("msg=[% x]\n", buf)
	}
	return nil
}

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

	/**
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
	**/

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
