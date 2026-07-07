// Package main — packet_streamer.go
// Streams raw packet bytes to a UDP destination in real-time as PCAPs are written.
// Enabled via --stream-host and --stream-port flags at startup.
// Each packet is sent as raw bytes (identical to PCAP payload) over UDP.
// If the destination is unreachable, packets are silently dropped and a
// warning is logged — streaming never blocks or fails attack execution.
package main

import (
	"fmt"
	"net"
	"sync"
)

var (
	globalStreamer     *PacketStreamer
	globalStreamerOnce sync.Once
)

// PacketStreamer holds the UDP connection used to stream raw packet bytes.
type PacketStreamer struct {
	conn *net.UDPConn
	addr *net.UDPAddr
	mu   sync.Mutex
}

// initPacketStreamer creates the global UDP streamer targeting host:port.
// Called once at startup if --stream-host and --stream-port are provided.
func initPacketStreamer(host string, port int) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("initPacketStreamer resolve %s:%d: %w", host, port, err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("initPacketStreamer dial %s:%d: %w", host, port, err)
	}

	globalStreamer = &PacketStreamer{conn: conn, addr: addr}
	logInfo("initPacketStreamer ready target=%s:%d", host, port)
	return nil
}

// streamPacket sends a single raw packet to the configured UDP destination.
// No-ops silently if the streamer is not initialised.
func streamPacket(pkt []byte) {
	if globalStreamer == nil || len(pkt) == 0 {
		return
	}
	globalStreamer.mu.Lock()
	defer globalStreamer.mu.Unlock()
	if _, err := globalStreamer.conn.Write(pkt); err != nil {
		logWarn("streamPacket write: %v", err)
	}
}
