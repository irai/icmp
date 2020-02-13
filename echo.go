package icmp

import (
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

type icmpEntry struct {
	msgRecv *icmp.Message
	expire  time.Time
}

var icmpTable = struct {
	echoIdentifier uint16
	mutex          sync.Mutex
	cond           *sync.Cond
	table          map[uint16]*icmpEntry
}{
	echoIdentifier: 5000,
	table:          make(map[uint16]*icmpEntry),
}

func init() {
	icmpTable.cond = sync.NewCond(&icmpTable.mutex)
}

// SendICMPEcho transmit an icmp echo request
// Do not wait for response
func (h *Handler) SendICMPEcho(src net.IP, dst net.IP, id uint16, seq uint16) error {

	icmpMessage := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(id),
			Seq:  int(seq),
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	p, err := icmpMessage.Marshal(nil)
	if err != nil {
		log.Error("cannot marshal ", err)
		return err
	}

	if err = h.sendRawICMP(src, dst, p); err != nil {
		log.Error("cannot marshal ", err)
		return err
	}

	return nil
}

// Ping send a ping request and wait for a reply
func (h *Handler) Ping(src net.IP, dst net.IP, timeout time.Duration) (err error) {

	icmpTable.cond.L.Lock()
	msg := icmpEntry{expire: time.Now().Add(timeout)}
	id := icmpTable.echoIdentifier
	icmpTable.echoIdentifier++
	icmpTable.table[id] = &msg
	icmpTable.cond.L.Unlock()

	if err = h.SendICMPEcho(src, dst, id, 0); err != nil {
		log.Error("error sending ", err)
		return err
	}

	icmpTable.cond.L.Lock()
	for msg.msgRecv == nil && msg.expire.After(time.Now()) {
		icmpTable.cond.Wait()
	}
	delete(icmpTable.table, id)
	icmpTable.cond.L.Unlock()

	if msg.msgRecv == nil {
		return fmt.Errorf("timeout id=%v", id)
	}

	return nil
}
