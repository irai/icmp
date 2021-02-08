package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/irai/icmp"
	"github.com/irai/icmp/icmp6"
)

var (
	srcIP = flag.String("src", "192.168.0.5", "source IP for originating packet")
	dstIP = flag.String("dst", "192.168.0.1", "destination IP for target packet")
	nic   = flag.String("nic", "eth0", "nic interface to listent to")
)

func main() {
	flag.Parse()

	icmp.LogAll = true
	log.SetLevel(log.DebugLevel)

	fmt.Printf("icmpListener: Listen and send icmp messages\n")
	fmt.Printf("Using nic %v src=%v dst=%v\n", *nic, *srcIP, *dstIP)

	iif, err := net.InterfaceByName(*nic)
	if err != nil {
		fmt.Printf("error opening nic=%s: %s\n", *nic, err)
		iif, _ := net.Interfaces()
		fmt.Printf("available interfaces\n")
		for _, v := range iif {
			addrs, _ := v.Addrs()
			fmt.Printf("  name=%s mac=%s\n", v.Name, v.HardwareAddr)
			for _, v := range addrs {
				fmt.Printf("    ip=%s\n", v)
			}
		}
		return
	}

	src := net.ParseIP(*srcIP).To4()
	if src.IsUnspecified() {
		log.Fatal("Invalid src IP ", srcIP)
	}

	dst := net.ParseIP(*dstIP).To4()
	if dst.IsUnspecified() {
		log.Fatal("Invalid dst IP ", dstIP)
	}

	ctxt, cancel := context.WithCancel(context.Background())

	// ICMPv4
	h4, err := icmp.New(*nic)
	if err != nil {
		log.Fatalf("Failed to create icmp nic=%s handler: ", *nic, err)
	}
	defer h4.Close()

	go func() {
		if err := h4.ListenAndServe(ctxt); err != nil {
			log.Error("icmp4.ListenAndServe terminated unexpectedly: ", err)
		}
	}()

	// ICMPv6

	ula, _ := icmp6.GenerateULA(iif.HardwareAddr, 0)
	fmt.Printf("IPv6 Unicast Local Address: %s\n", ula)

	h6, err := icmp6.New(*nic)
	if err != nil {
		log.Fatalf("Failed to create icmp6 nic=%s handler: ", *nic, err)
	}
	defer h6.Close()

	go func() {
		if err := h6.ListenAndServe(ctxt); err != nil {
			log.Error("icmp6.ListenAndServe terminated unexpectedly: ", err)
		}
	}()

	time.Sleep(time.Millisecond * 200) //wait time to open sockets
	cmd(h4, h6, src, dst)

	cancel()
}

func cmd(h *icmp.Handler, h6 *icmp6.Handler, srcIP net.IP, dstIP net.IP) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit            | (p)ing ip | (l)list | (g) loG <level>")
		fmt.Println("    ndp: (ra) ip6          | ")
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		text = strings.ToLower(text[:len(text)-1])

		// handle windows line feed
		if len(text) > 1 && text[len(text)-1] == '\r' {
			text = strings.ToLower(text[:len(text)-1])
		}

		if text == "" {
			continue
		}
		tokens := strings.Split(text, " ")

		switch tokens[0] {
		case "q":
			return
		case "l":
			h6.PrintTable()
		case "g":
			if icmp.LogAll {
				fmt.Printf("Debugging is OFF\n")
				icmp.LogAll = false
			} else {
				fmt.Printf("Debugging is ON\n")
				icmp.LogAll = true
			}
		case "p":
			if len(tokens) < 2 {
				fmt.Println("missing ip")
				continue
			}
			ip := net.ParseIP(tokens[1])
			if ip == nil || ip.IsUnspecified() {
				fmt.Println("invalid ip=", ip)
				continue
			}
			now := time.Now()
			if ip.To4() != nil {
				if err := h.Ping(srcIP, dstIP, time.Second*4); err != nil {
					fmt.Println("ping error ", err)
					continue
				}
				fmt.Printf("ping %v time=%v\n", dstIP, time.Now().Sub(now))
			}
			if ip.To16() != nil && ip.To4() == nil {
				if err := h6.SendEcho(nil, ip, 1, 101); err != nil {
					fmt.Println("icmp6 echo error ", err)
					continue
				}
				fmt.Printf("ping %v time=%v\n", dstIP, time.Now().Sub(now))
			}
		case "ra":
			if len(tokens) < 2 {
				fmt.Println("missing address")
				continue
			}
			/**
			ip := net.ParseIP(tokens[1])
			if err := h6.RouterAdvertisement(&net.IPAddr{IP: ip}); err != nil {
				log.Printf("error sending ra: %v", err)
				continue
			}
			**/
		}
	}
}
