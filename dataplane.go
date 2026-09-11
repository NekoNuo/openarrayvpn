package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"
)

// killReasons maps ATP_AG_KILL_TUNNEL reason codes (control cmd 2,
// bytes 16-19 big-endian), from the official client's handle_atp_packets.
var killReasons = map[uint32]string{
	1:   "account logged in elsewhere",
	2:   "session invalid",
	3:   "session expired",
	8:   "session logged out",
	0xe: "second session with same client id",
	0xf: "server requests VPN restart",
}

// controlPacketError classifies a proto-0xff control packet.
// Cmd 1 is a keepalive — logged only, never answered (the server reflects
// DPD packets; echoing causes a storm). Cmd 2 is ATP_AG_KILL_TUNNEL; the
// BE uint32 at bytes 16-19 carries the reason.
func controlPacketError(pkt []byte, iplen int) (bool, error) {
	if pkt[0] != 0x45 || pkt[9] != 0xff {
		return false, nil
	}
	ctrlType := binary.BigEndian.Uint16(pkt[12:14])
	switch ctrlType {
	case 1:
		if verbose {
			log.Printf("keepalive from server")
		}
	case 2:
		if iplen >= 20 {
			reason := binary.BigEndian.Uint32(pkt[16:20])
			text := killReasons[reason]
			if text == "" {
				text = "unknown"
			}
			return true, fmt.Errorf("tunnel killed by server: %s (reason %d)", text, reason)
		}
	default:
		log.Printf("control packet cmd %#x", ctrlType)
	}
	return true, nil
}

// Run is the tunnel data plane: reassembles IP packets from the TLS stream
// (packets may be batched or split across records, mirroring the official
// handle_ssl_tunnel) and sends DPD keepalives. Returns when the connection
// dies; reconnect policy (always re-login) is ours, not the official one.
func (t *Tunnel) Run(st *Stack) error {
	done := make(chan struct{})
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		t.keepaliveLoop(errCh, done)
	}()
	go func() {
		defer wg.Done()
		errCh <- t.readLoop(st)
	}()
	err := <-errCh
	close(done)
	t.conn.Close() // unblock the other goroutine
	wg.Wait()      // no more inbound injections after Run returns
	return err
}

func (t *Tunnel) readLoop(st *Stack) error {
	buf := make([]byte, 0, 65536)
	tmp := make([]byte, 65536)
	for {
		n, err := t.conn.Read(tmp)
		if err != nil {
			return fmt.Errorf("tunnel read: %w", err)
		}
		t.lastRx.Store(time.Now().UnixNano())
		buf = append(buf, tmp[:n]...)

		for len(buf) >= 20 {
			var iplen int
			switch buf[0] >> 4 {
			case 4:
				iplen = int(binary.BigEndian.Uint16(buf[2:4]))
			case 6:
				iplen = int(binary.BigEndian.Uint16(buf[4:6])) + 40
			default:
				log.Printf("unrecognised packet %x (len %d), dropping stream bytes", buf[:min(16, len(buf))], len(buf))
				buf = nil
				continue
			}
			if iplen < 20 || iplen > 65535 {
				buf = nil
				continue
			}
			if iplen > len(buf) {
				break // partial packet, wait for more
			}
			pkt := buf[:iplen]
			buf = buf[iplen:]

			// Control packets (proto 0xff): cmd at bytes 12-13 (BE).
			handled, ctrlErr := controlPacketError(pkt, iplen)
			if handled {
				if ctrlErr != nil {
					return ctrlErr
				}
				continue
			}
			cp := make([]byte, iplen)
			copy(cp, pkt)
			if verbose {
				log.Printf("rx %s", pktDesc(cp))
			}
			st.Inject(cp)
		}
	}
}

func (t *Tunnel) keepaliveLoop(errCh chan<- error, done <-chan struct{}) {
	interval := time.Duration(t.Keepalive) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		sinceRx := time.Since(time.Unix(0, t.lastRx.Load()))
		if sinceRx > 4*interval {
			errCh <- fmt.Errorf("no data from server for %s, dead peer", sinceRx.Round(time.Second))
			return
		}
		if time.Since(time.Unix(0, t.lastTx.Load())) >= interval {
			if err := t.WritePacket(dpdPkt); err != nil {
				errCh <- fmt.Errorf("send DPD: %w", err)
				return
			}
		}
	}
}
