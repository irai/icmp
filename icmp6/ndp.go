package icmp6

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/mdlayher/netx/rfc4193"

	"golang.org/x/net/ipv6"
)

// Handler implements ICMPv6 Neighbor Discovery Protocol
// see: https://mdlayher.com/blog/network-protocol-breakdown-ndp-and-go/
type Handler struct {
	pc       *ipv6.PacketConn
	mutex    sync.Mutex
	prefixes []net.IPNet
	ifi      *net.Interface
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

func (s *Handler) SetPrefixes(prefixes []net.IPNet) error {
	s.mutex.Lock()
	s.prefixes = prefixes
	s.mutex.Unlock()
	return s.RouterAdvertisement(nil)
}

func (s *Handler) RouterAdvertisement(addr net.Addr) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.prefixes == nil {
		return nil // nothing to do
	}
	if addr == nil {
		addr = &net.IPAddr{
			IP:   net.IPv6linklocalallnodes,
			Zone: s.ifi.Name,
		}
	}

	var options []ndp.Option

	if len(s.prefixes) > 0 {
		addrs, err := s.ifi.Addrs()
		if err != nil {
			return err
		}
		var linkLocal net.IP
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipv6LinkLocal.Contains(ipnet.IP) {
				linkLocal = ipnet.IP
				break
			}
		}
		if !linkLocal.Equal(net.IPv6zero) {
			options = append(options, &ndp.RecursiveDNSServer{
				Lifetime: 30 * time.Minute,
				Servers:  []net.IP{linkLocal},
			})
		}
	}

	for _, prefix := range s.prefixes {
		ones, _ := prefix.Mask.Size()
		// Use the first /64 subnet within larger prefixes
		if ones < 64 {
			ones = 64
		}

		options = append(options, &ndp.PrefixInformation{
			PrefixLength:                   uint8(ones),
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  2 * time.Hour,
			PreferredLifetime:              30 * time.Minute,
			Prefix:                         prefix.IP,
		})
	}

	options = append(options,
		&ndp.DNSSearchList{
			// TODO: audit all lifetimes and express them in relation to each other
			Lifetime: 20 * time.Minute,
			// TODO: single source of truth for search domain name
			DomainNames: []string{"lan"},
		},
		ndp.NewMTU(uint32(s.ifi.MTU)),
		&ndp.LinkLayerAddress{
			Direction: ndp.Source,
			Addr:      s.ifi.HardwareAddr,
		},
	)

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  30 * time.Minute,
		Options:         options,
	}

	mb, err := ndp.MarshalMessage(ra)
	if err != nil {
		return err
	}
	log.Printf("sending to %s", addr)
	if _, err := s.pc.WriteTo(mb, nil, addr); err != nil {
		return err
	}
	return nil
}

func (s *Handler) serve(ctxt context.Context, conn net.PacketConn) error {

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
	**/

	go func() {
		for {
			s.RouterAdvertisement(nil) // TODO: handle error
			time.Sleep(1 * time.Minute)
		}
	}()

	buf := make([]byte, s.ifi.MTU)
	for {
		n, cm, addr, err := s.pc.ReadFrom(buf)
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

		// This will parse and create a struct; should optimise this to use references to buffer
		msg, err := ndp.ParseMessage(buf[:n])
		if err != nil {
			fmt.Printf("Invalid icmp6 msg cm=%+v: %s\n", cm, err)
			fmt.Printf("msg=[% x]\n", buf[:n])
			continue
		}

		switch msg.Type() {

		case ipv6.ICMPTypeRouterSolicitation:
			fmt.Printf("icmp6 router solicitation: %+v %+v", cm, msg)
			if err := s.RouterAdvertisement(addr); err != nil {
				fmt.Printf("error in icmp6 router advertisement: %s", err)
				continue
			}

		case ipv6.ICMPTypeRouterAdvertisement:
			fmt.Printf("icmp6 router advertisement: %+v %+v", cm, msg)
			// m = new(RouterAdvertisement)

		case ipv6.ICMPTypeNeighborAdvertisement:
			fmt.Printf("icmp6 neighbor advertisement: %+v %+v", cm, msg)
			// msg = ndp.NeighborAdvertisement(msg)

		case ipv6.ICMPTypeNeighborSolicitation:
			fmt.Printf("icmp6 neighbor solicitation: %+v %+v", cm, msg)
			// m = new(NeighborSolicitation)

		default:
			log.Printf("icmp6 not implemented %+v msg=%+v", cm, msg)
			fmt.Printf("msg=[% x]\n", buf[:n])
		}
	}

}

func (s *Handler) ListenAndServe(ctxt context.Context) error {
	// TODO(correctness): would it be better to listen on
	// net.IPv6linklocalallrouters? Just specifying that results in an error,
	// though.
	conn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{IP: net.IPv6unspecified, Zone: ""})
	if err != nil {
		return err
	}
	return s.serve(ctxt, conn)
}
