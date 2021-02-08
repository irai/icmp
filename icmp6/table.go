package icmp6

import (
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/netx/rfc4193"

	"golang.org/x/net/ipv6"
)

// Host holds a host identification
type Host struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Online   bool
	Router   bool
	LastSeen time.Time
}

// Router holds a router identification
type Router struct {
	MAC             net.HardwareAddr // LLA - Local link address
	IP              net.IP
	ManagedFlag     bool
	OtherCondigFlag bool
	MTU             uint32
	ReacheableTime  int // Must be no greater than 3,600,000 milliseconds (1hour)
	RetransTimer    int //
	CurHopLimit     uint8
	DefaultLifetime time.Duration // A value of zero means the router is not to be used as a default router
	Prefixes        []PrefixInformation
	RDNSS           *RecursiveDNSServer
	Options         []Option
}

// Event represents and ICMP6 event from a host
type Event struct {
	Type ipv6.ICMPType
	Host Host
}

// PrintTable logs ICMP6 tables to standard out
func (h *Handler) PrintTable() {
	if len(h.LANHosts) > 0 {
		fmt.Printf("icmp6 hosts table len=%v\n", len(h.LANHosts))
		for _, v := range h.LANHosts {
			fmt.Printf("mac=%s ip=%v online=%v router=%v\n", v.MAC, v.IP, v.Online, v.Router)
		}
	}
	if len(h.LANRouters) > 0 {
		fmt.Printf("icmp6 routers table len=%v\n", len(h.LANRouters))
		for _, v := range h.LANRouters {
			flags := ""
			if v.ManagedFlag {
				flags = flags + "M"
			}
			if v.OtherCondigFlag {
				flags = flags + "O"
			}
			fmt.Printf("mac=%s ip=%v flags=%s prefixes=%v rdnss=%s options=%v\n", v.MAC, v.IP, flags, v.Prefixes, v.RDNSS, v.Options)
		}
	}
}

func (h *Handler) findOrCreateHost(mac net.HardwareAddr, ip net.IP) (host *Host, found bool) {
	if host, ok := h.LANHosts[string(mac)]; ok {
		return host, true
	}
	host = &Host{MAC: mac, IP: ip}
	h.LANHosts[string(host.MAC)] = host
	return host, false
}

func (h *Handler) findOrCreateRouter(mac net.HardwareAddr) (router *Router, found bool) {
	if router, ok := h.LANRouters[string(mac)]; ok {
		return router, true
	}
	router = &Router{MAC: mac}
	h.LANRouters[string(router.MAC)] = router
	return router, false
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
