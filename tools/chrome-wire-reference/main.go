// chrome-wire-reference emits the first flight of the exact quic-go revision
// pinned by upstream Hysteria. It is intentionally a tiny, local-only probe for
// Quinn's ignored wire-parity test; it is not a client or release artifact.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	quic "github.com/apernet/quic-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: chrome-wire-reference HOST:PORT")
		os.Exit(2)
	}

	remote, err := net.ResolveUDPAddr("udp4", os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve target: %v\n", err)
		os.Exit(1)
	}
	packetConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open UDP socket: %v\n", err)
		os.Exit(1)
	}
	defer packetConn.Close()

	transport := &quic.Transport{
		Conn:                  packetConn,
		ConnectionIDGenerator: quic.ZeroLengthConnectionIDGenerator{},
	}
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = transport.DialEarly(ctx, remote, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // The probe never accepts a server flight.
		NextProtos:         []string{"h3"},
	}, &quic.Config{
		// These are Hysteria's ordinary inputs. ChromeParrot deliberately overrides
		// the values visible on the wire to Chrome's 6/15 MiB and 65536-byte profile.
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		MaxStreamReceiveWindow:         8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 20 * 1024 * 1024,
		MaxConnectionReceiveWindow:     20 * 1024 * 1024,
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           1200,
		OmitMaxDatagramFrameSize:       true,
		DisablePathManager:             true,
		ChromeParrot:                   true,
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(os.Stderr, "start ChromeParrot connection: %v\n", err)
		os.Exit(1)
	}
	// No server reply is intentional. The deadline ends the dial after its Initial
	// flight has been flushed to the local capture socket.
}
