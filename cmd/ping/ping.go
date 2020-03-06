package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/irai/icmp"
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

	log.Infof("Using nic %v src=%v dst=%v", *nic, *srcIP, *dstIP)

	src := net.ParseIP(*srcIP).To4()
	if src.IsUnspecified() {
		log.Fatal("Invalid src IP ", srcIP)
	}

	dst := net.ParseIP(*dstIP).To4()
	if dst.IsUnspecified() {
		log.Fatal("Invalid dst IP ", dstIP)
	}

	h, _ := icmp.New(*nic)
	icmp.LogAll = true
	defer h.Close()

	cmd(h, src, dst)
}

func cmd(h *icmp.Handler, srcIP net.IP, dstIP net.IP) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit | (p)ing src dst | (g) loG <level>")
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		text = strings.ToLower(text[:len(text)-1])
		fmt.Println(text)

		if text == "" || len(text) < 1 {
			continue
		}

		switch text[0] {
		case 'q':
			return
		case 'l':
			if len(text) < 3 {
				text = text + "   "
			}
			err := setLogLevel(text[2:])
			if err != nil {
				log.Error("invalid level. valid levels (error, warn, info, debug) ", err)
				break
			}
		case 'p':
			now := time.Now()
			if err := h.Ping(srcIP, dstIP, time.Second*4); err != nil {
				log.Error("ping error ", err)
				continue
			}
			fmt.Printf("ping %v time=%v\n", dstIP, time.Now().Sub(now))
		}
	}
}

func setLogLevel(level string) (err error) {

	if level != "" {
		l, err := log.ParseLevel(level)
		if err != nil {
			return err
		}
		log.SetLevel(l)
	}

	return nil
}
