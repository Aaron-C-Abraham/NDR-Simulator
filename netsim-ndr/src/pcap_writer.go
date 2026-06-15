// Package main — pcap_writer.go
// Writes captured packets to PCAP files (libpcap format) for PCAP-capable devices.
package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var defaultEthernetFrameProtocol = 0x0800

// GlobalPCAPDir is the output directory for PCAP files.
var GlobalPCAPDir string
var defaultDuration uint64 = 0

// var openPorts = []uint16{22, 80, 443, 3389, 8080, 8443}

// GlobalPCAPWriteLock protects concurrent PCAP writes.
var GlobalPCAPWriteLock sync.Mutex

// PCAPGlobalHeader is the 24-byte libpcap file header.
type PCAPGlobalHeader struct {
	MagicNumber  uint32 // 0xa1b2c3d4
	VersionMajor uint16 // 2
	VersionMinor uint16 // 4
	ThisZone     int32  // 0
	SigFigs      uint32 // 0
	SnapLen      uint32 // 65535
	Network      uint32 // 1 = LINKTYPE_ETHERNET
}

// PCAPRecordHeader is the 16-byte per-packet header.
type PCAPRecordHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32 // saved length
	OrigLen uint32 // original length
}

// initPCAPWriter creates the PCAP output directory.
func initPCAPWriter() error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering initPCAPWriter")

	GlobalPCAPDir = configString("output.pcap.dir", "output/pcap")
	if err := ensureDir(GlobalPCAPDir); err != nil {
		logError("initPCAPWriter ensureDir: %v", err)
		return err
	}
	logInfo("Return from initPCAPWriter dir=%s", GlobalPCAPDir)
	return nil
}

// writePCAPFile creates a new PCAP file containing the given raw ethernet frames.
func writePCAPFile(runID, attackName string, packets [][]byte, duration uint64) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering writePCAPFile runID=%s attack=%s packets=%d", runID, attackName, len(packets))

	filename := fmt.Sprintf("%s_%s_%s.pcap", runID, attackName, time.Now().Format("20060102_150405"))
	path := filepath.Join(GlobalPCAPDir, filename)

	GlobalPCAPWriteLock.Lock()
	defer GlobalPCAPWriteLock.Unlock()

	file, err := os.Create(path)
	if err != nil {
		logError("writePCAPFile create %s: %v", path, err)
		return "", err
	}
	defer file.Close()

	// Write global header
	ghdr := PCAPGlobalHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      65535,
		Network:      1,
	}
	if err = binary.Write(file, binary.LittleEndian, ghdr); err != nil {
		logError("writePCAPFile global header: %v", err)
		return "", err
	}

	// Write packet records
	for _, pkt := range packets {
		// ts := now.Add(time.Duration(idx) * 100 * time.Millisecond)
		ts := time.Now()
		if duration > 0 {
			sleepTime := time.Second / time.Duration(duration)
			time.Sleep(sleepTime)
		}
		rhdr := PCAPRecordHeader{
			TsSec:   uint32(ts.Unix()),
			TsUsec:  uint32(ts.Nanosecond() / 1000),
			InclLen: uint32(len(pkt)),
			OrigLen: uint32(len(pkt)),
		}
		if err = binary.Write(file, binary.LittleEndian, rhdr); err != nil {
			logError("writePCAPFile record header: %v", err)
			return "", err
		}
		if _, err = file.Write(pkt); err != nil {
			logError("writePCAPFile packet data: %v", err)
			return "", err
		}
	}

	logInfo("Return from writePCAPFile path=%s", path)
	return path, nil
}

// buildEthernetFrame wraps an IP payload in an Ethernet frame.
func buildEthernetFrame(srcMAC, dstMAC [6]byte, ipPayload []byte) []byte {
	frame := make([]byte, 14+len(ipPayload))
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	frame[12] = 0x08
	frame[13] = 0x00
	copy(frame[14:], ipPayload)
	return frame
}
func buildEthernetFrameARP(srcMAC, dstMAC [6]byte, ipPayload []byte, protocol uint16) []byte {
	frame := make([]byte, 15+len(ipPayload))
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], protocol)
	frame[14] = 0x00
	copy(frame[15:], ipPayload)
	return frame
}

// buildIPv4Packet builds a minimal IPv4 packet.
func buildIPv4Packet(srcIP, dstIP string, protocol uint8, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // Version 4, IHL 5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:], uint16(rand.Intn(65535))) // ID
	pkt[8] = 64                                                   // TTL
	pkt[9] = protocol
	binary.BigEndian.PutUint32(pkt[12:], ipToUint32(srcIP))
	binary.BigEndian.PutUint32(pkt[16:], ipToUint32(dstIP))
	copy(pkt[20:], payload)
	// Compute checksum
	checksum := ipChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:], checksum)
	return pkt
}

// buildTCPSegment builds a minimal TCP segment.
func buildTCPSegment(srcPort, dstPort uint16, flags uint8, seq, ack uint32, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:], srcPort)
	binary.BigEndian.PutUint16(seg[2:], dstPort)
	binary.BigEndian.PutUint32(seg[4:], seq)
	binary.BigEndian.PutUint32(seg[8:], ack)
	seg[12] = 0x50 // Data offset = 5 (20 bytes), reserved = 0
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:], 65535) // Window size
	copy(seg[20:], payload)
	return seg
}

// buildICMPSegment builds a minimal ICMP segment
func buildICMPSegment(PacketType, Code byte, checksum, identifier, seq uint16, payload []byte) []byte {
	seg := make([]byte, 8+len(payload))
	seg[0] = PacketType
	seg[1] = Code
	binary.BigEndian.PutUint16(seg[2:], checksum)
	binary.BigEndian.PutUint16(seg[4:], identifier)
	binary.BigEndian.PutUint16(seg[6:], seq)
	copy(seg[8:], payload)
	return seg
}

// buildUDPDatagram builds a minimal UDP datagram.
func buildUDPDatagram(srcPort, dstPort uint16, payload []byte) []byte {
	dgram := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(dgram[0:], srcPort)
	binary.BigEndian.PutUint16(dgram[2:], dstPort)
	binary.BigEndian.PutUint16(dgram[4:], uint16(8+len(payload)))
	copy(dgram[8:], payload)
	return dgram
}

// ipChecksum calculates the ones-complement checksum for an IP header.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for idx := 0; idx < len(hdr)-1; idx += 2 {
		sum += uint32(hdr[idx])<<8 | uint32(hdr[idx+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// parseMACAddress converts a MAC string "aa:bb:cc:dd:ee:ff" to [6]byte.
func parseMACAddress(mac string) [6]byte {
	var result [6]byte
	if len(mac) != 17 {
		return result
	}
	for idx := 0; idx < 6; idx++ {
		offset := idx * 3
		hi := hexNibble(mac[offset])
		lo := hexNibble(mac[offset+1])
		result[idx] = (hi << 4) | lo
	}
	return result
}

// hexNibble converts a hex character to its nibble value.
func hexNibble(ch byte) byte {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0'
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10
	default:
		return 0
	}
}

// --- PCAP generation for attack scenarios ---

// PCAPPortScan generates PCAP frames for a port scan attack.
func PCAPPortScan(attackerDev, targetDev *Device, ports []uint16, port_mapping map[uint16]string) ([]byte, string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPPortScan attacker=%s target=%s ports=%d", attackerDev.IPAddress, targetDev.IPAddress, len(ports))
	srcMAC := parseMACAddress(attackerDev.MACAddress)
	dstMAC := parseMACAddress(targetDev.MACAddress)

	var frames [][]byte
	for _, port := range ports {
		switch port_mapping[port] {
		case "Open":
			src_port := randomPort()
			seq := rand.Uint32()
			// SYN packet
			tcpSyn := buildTCPSegment(src_port, port, 0x02, seq, 0, nil)
			ipPkt := buildIPv4Packet(attackerDev.IPAddress, targetDev.IPAddress, 6, tcpSyn)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ipPkt))
			// SYN/ACK response (open port)
			tcpSynAck := buildTCPSegment(port, src_port, 0x12, 0, seq+1, nil)
			ipSynAck := buildIPv4Packet(targetDev.IPAddress, attackerDev.IPAddress, 6, tcpSynAck)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, ipSynAck))

			tcpAck := buildTCPSegment(src_port, port, 0x10, seq+1, 1, nil)
			ipAck := buildIPv4Packet(attackerDev.IPAddress, targetDev.IPAddress, 6, tcpAck)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ipAck))
		case "Close":
			src_port := randomPort()
			seq := rand.Uint32()
			// SYN packet
			tcpSyn := buildTCPSegment(src_port, port, 0x02, seq, 0, nil)
			ipPkt := buildIPv4Packet(attackerDev.IPAddress, targetDev.IPAddress, 6, tcpSyn)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ipPkt))
			// RST/ACK response (target rejects)
			tcpRst := buildTCPSegment(port, src_port, 0x14, 0, seq, nil)
			ipRst := buildIPv4Packet(targetDev.IPAddress, attackerDev.IPAddress, 6, tcpRst)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, ipRst))

		}
	}
	path, err := writePCAPFile("scan", "portscan", frames, defaultDuration)
	logInfo("Return from PCAPPortScan frames=%d path=%s", len(frames), path)
	return nil, path, err
}

// PCAPBeaconing generates PCAP frames for C2 beaconing.
func PCAPBeaconing(infectedDev *Device, c2IP string, count int) ([]byte, string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPBeaconing device=%s c2=%s count=%d", infectedDev.Name, c2IP, count)

	srcMAC := parseMACAddress(infectedDev.MACAddress)
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x02} // C2 server MAC

	var frames [][]byte
	for idx := 0; idx < count; idx++ {
		// HTTP GET beacon
		beaconPayload := []byte(fmt.Sprintf("GET /update?id=%s HTTP/1.1\r\nHost: %s\r\n\r\n", randomHexString(16), c2IP))
		tcpPsh := buildTCPSegment(randomPort(), 443, 0x18, rand.Uint32(), rand.Uint32(), beaconPayload)
		ipPkt := buildIPv4Packet(infectedDev.IPAddress, c2IP, 6, tcpPsh)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ipPkt))

		// C2 response
		c2Response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		tcpAck := buildTCPSegment(443, randomPort(), 0x18, rand.Uint32(), rand.Uint32(), c2Response)
		ipResp := buildIPv4Packet(c2IP, infectedDev.IPAddress, 6, tcpAck)

		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, ipResp))
	}

	path, err := writePCAPFile("beacon", "beaconing", frames, defaultDuration)
	logInfo("Return from PCAPBeaconing frames=%d path=%s", len(frames), path)
	return nil, path, err
}

// PCAPDNSTunnel generates PCAP frames for DNS tunneling.
func PCAPDNSTunnel(infectedDev, dnsDev *Device, domain string, count int) ([]byte, string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPDNSTunnel device=%s dns=%s domain=%s count=%d", infectedDev.Name, dnsDev.IPAddress, domain, count)

	srcMAC := parseMACAddress(infectedDev.MACAddress)
	dstMAC := parseMACAddress(dnsDev.MACAddress)

	var frames [][]byte
	for idx := 0; idx < count; idx++ {
		// DNS TXT query with long subdomain (data exfil)
		subdomain := randomHexString(32) + "." + domain
		dnsQuery := buildDNSQuery(subdomain)
		udpPkt := buildUDPDatagram(randomPort(), 53, dnsQuery)
		ipPkt := buildIPv4Packet(infectedDev.IPAddress, dnsDev.IPAddress, 17, udpPkt)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ipPkt))
	}

	path, err := writePCAPFile("dnstunn", "dns_tunnel", frames, defaultDuration)
	logInfo("Return from PCAPDNSTunnel frames=%d path=%s", len(frames), path)
	return nil, path, err
}

// buildDNSQuery builds a minimal DNS query packet for a given domain.
func buildDNSQuery(domain string) []byte {
	buf := make([]byte, 0, 50)
	// Transaction ID
	buf = append(buf, 0xAB, 0xCD)
	// Flags: standard query
	buf = append(buf, 0x01, 0x00)
	// QDCOUNT=1
	buf = append(buf, 0x00, 0x01)
	// ANCOUNT, NSCOUNT, ARCOUNT = 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Question section: encode domain
	parts := splitDomain(domain)
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)       // null terminator
	buf = append(buf, 0x00, 0x10) // QTYPE = TXT
	buf = append(buf, 0x00, 0x01) // QCLASS = IN
	return buf
}

// ─── Additional PCAP generators (Option B) ───────────────────────────────────

// PCAPSYNFlood generates PCAP frames for a SYN flood from multiple spoofed sources.
func PCAPSYNFlood(runID, targetIP string, targetPort uint16, sourceIPs []string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPSYNFlood target=%s port=%d sources=%d", targetIP, targetPort, len(sourceIPs))

	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	var frames [][]byte
	for _, srcIP := range sourceIPs {
		srcMAC := [6]byte{0x00, byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))}
		syn := buildTCPSegment(randomPort(), targetPort, 0x02, rand.Uint32(), 0, nil)
		ip := buildIPv4Packet(srcIP, targetIP, 6, syn)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))
	}

	path, err := writePCAPFile(runID, "syn_flood", frames, defaultDuration)
	logInfo("Return from PCAPSYNFlood frames=%d path=%s", len(frames), path)
	return path, err
}

// PCAPUDPFlood generates PCAP frames for a UDP flood.
func PCAPUDPFlood(runID, targetIP string, targetPort uint16, sourceIPs []string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPUDPFlood target=%s port=%d sources=%d", targetIP, targetPort, len(sourceIPs))

	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	payload := make([]byte, 512)
	rand.Read(payload)
	var frames [][]byte
	for _, srcIP := range sourceIPs {
		srcMAC := [6]byte{0x00, byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))}
		udp := buildUDPDatagram(randomPort(), targetPort, payload)
		ip := buildIPv4Packet(srcIP, targetIP, 17, udp)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))
	}

	path, err := writePCAPFile(runID, "udp_flood", frames, defaultDuration)
	logInfo("Return from PCAPUDPFlood frames=%d path=%s", len(frames), path)
	return path, err
}

// PCAPHTTPFlood generates PCAP frames for a Layer-7 HTTP flood.
func PCAPHTTPFlood(runID, attackerIP, targetIP string, targetPort uint16, count int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPHTTPFlood attacker=%s target=%s port=%d count=%d", attackerIP, targetIP, targetPort, count)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x44}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	var frames [][]byte
	for idx := 0; idx < count; idx++ {
		payload := []byte(fmt.Sprintf(
			"GET /?r=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
			randomHexString(8), targetIP))
		syn := buildTCPSegment(randomPort(), targetPort, 0x18, rand.Uint32(), rand.Uint32(), payload)
		ip := buildIPv4Packet(attackerIP, targetIP, 6, syn)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))
	}

	path, err := writePCAPFile(runID, "http_flood", frames, defaultDuration)
	logInfo("Return from PCAPHTTPFlood frames=%d path=%s", len(frames), path)
	return path, err
}

// PCAPSlowloris generates PCAP frames representing Slowloris partial HTTP headers.
func PCAPSlowloris(runID, attackerIP, targetIP string, connections int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPSlowloris attacker=%s target=%s connections=%d", attackerIP, targetIP, connections)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x55}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	var frames [][]byte
	for idx := 0; idx < connections; idx++ {
		srcPort := randomPort()
		seq := rand.Uint32()

		// SYN
		syn := buildTCPSegment(srcPort, 80, 0x02, seq, 0, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))

		// Partial header (never a complete request)
		partial := []byte(fmt.Sprintf("GET /?%s HTTP/1.1\r\nHost: %s\r\n", randomHexString(8), targetIP))
		psh := buildTCPSegment(srcPort, 80, 0x18, seq+1, 1, partial)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, psh)))

		// Keep-alive header drip
		drip := []byte("X-a: b\r\n")
		drip2 := buildTCPSegment(srcPort, 80, 0x18, seq+uint32(1+len(partial)), 1, drip)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, drip2)))
	}

	path, err := writePCAPFile(runID, "slowloris", frames, defaultDuration)
	logInfo("Return from PCAPSlowloris frames=%d path=%s", len(frames), path)
	return path, err
}

// PCAPBruteForce generates PCAP frames for a login brute-force attack.
// protocol: "ssh", "rdp", or "smb"
func PCAPBruteForce(runID, attackerIP, targetIP string, targetPort uint16, protocol string, attempts int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPBruteForce attacker=%s target=%s proto=%s attempts=%d", attackerIP, targetIP, protocol, attempts)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x66}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	var frames [][]byte

	for idx := 0; idx < attempts; idx++ {
		srcPort := randomPort()
		seq := rand.Uint32()

		// SYN
		syn := buildTCPSegment(srcPort, targetPort, 0x02, seq, 0, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))

		// Protocol-specific banner/handshake
		var handshake []byte
		switch protocol {
		case "ssh":
			handshake = []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
		case "rdp":
			handshake = rdpClientPDU[:]
		case "smb":
			handshake = smbNegotiatePDU[:]
		default:
			handshake = []byte(fmt.Sprintf("USER admin\r\nPASS %s\r\n", randomHexString(8)))
		}
		data := buildTCPSegment(srcPort, targetPort, 0x18, seq+1, 1, handshake)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, data)))

		// RST (auth failure)
		rst := buildTCPSegment(targetPort, srcPort, 0x04, 0, 0, nil)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, rst)))
	}

	path, err := writePCAPFile(runID, "bruteforce_"+protocol, frames, defaultDuration)
	logInfo("Return from PCAPBruteForce frames=%d path=%s", len(frames), path)
	return path, err
}

// PCAPExfil generates PCAP frames for HTTP data exfiltration.
func PCAPExfil(runID, attackerIP, targetIP string, targetPort uint16, dataMB int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPExfil attacker=%s target=%s port=%d dataMB=%d", attackerIP, targetIP, targetPort, dataMB)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x77}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	seq := rand.Uint32()
	srcPort := randomPort()

	// HTTP POST with body size indicating large exfil
	httpHeader := []byte(fmt.Sprintf(
		"POST /upload?token=%s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
		randomHexString(16), targetIP, dataMB*1024*1024))
	chunk := make([]byte, 1400) // MTU-sized payload chunks
	rand.Read(chunk)

	var frames [][]byte
	// SYN
	syn := buildTCPSegment(srcPort, targetPort, 0x02, seq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))

	// POST header
	headerPkt := buildTCPSegment(srcPort, targetPort, 0x18, seq+1, 1, httpHeader)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, headerPkt)))

	// Data chunks (simulate 10 chunk packets regardless of dataMB)
	chunkSeq := seq + uint32(1+len(httpHeader))
	for idx := 0; idx < 10; idx++ {
		data := buildTCPSegment(srcPort, targetPort, 0x18, chunkSeq, 1, chunk)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, data)))
		chunkSeq += uint32(len(chunk))
	}

	path, err := writePCAPFile(runID, "exfil_http", frames, defaultDuration)
	logInfo("Return from PCAPExfil frames=%d path=%s", len(frames), path)
	return path, err
}

// PCAPLateral generates PCAP frames for SMB lateral movement.
func PCAPLateral(runID, attackerIP, targetIP string, targetPort uint16) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPLateral attacker=%s target=%s port=%d", attackerIP, targetIP, targetPort)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x88}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	seq := rand.Uint32()

	var frames [][]byte

	// TCP SYN to SMB
	syn := buildTCPSegment(srcPort, targetPort, 0x02, seq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))

	// SMB Negotiate
	neg := buildTCPSegment(srcPort, targetPort, 0x18, seq+1, 1, smbNegotiatePDU[:])
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, neg)))

	// Session Setup (simulated NTLM)
	ntlmHdr := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00} // NTLMSSP\0
	sess := buildTCPSegment(srcPort, targetPort, 0x18, seq+uint32(1+len(smbNegotiatePDU)), 1, ntlmHdr)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, sess)))

	// Tree connect to C$ share
	treePayload := []byte(fmt.Sprintf("\\\\%s\\C$", targetIP))
	tree := buildTCPSegment(srcPort, targetPort, 0x18, seq+uint32(1+len(smbNegotiatePDU)+len(ntlmHdr)), 1, treePayload)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, tree)))

	path, err := writePCAPFile(runID, "lateral_smb", frames, defaultDuration)
	logInfo("Return from PCAPLateral frames=%d path=%s", len(frames), path)
	return path, err
}

// PCAPARPSweep generates PCAP frames for an ARP broadcast sweep.
func PCAPARPSweep(runID, attackerIP string, subnet string, count int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPARPSweep attacker=%s subnet=%s count=%d", attackerIP, subnet, count)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x99}
	broadcastMAC := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	var frames [][]byte

	parts := strings.Split(subnet, ".")
	prefix := "10.0.1"
	if len(parts) >= 3 {
		prefix = parts[0] + "." + parts[1] + "." + parts[2]
	}

	for idx := 1; idx <= count; idx++ {
		targetIP := fmt.Sprintf("%s.%d", prefix, idx)
		// ARP request payload: who-has targetIP tell attackerIP
		arp := buildARPRequest(srcMAC, attackerIP, targetIP)
		// ARP uses EtherType 0x0806
		frame := make([]byte, 14+len(arp))
		copy(frame[0:6], broadcastMAC[:])
		copy(frame[6:12], srcMAC[:])
		frame[12] = 0x08
		frame[13] = 0x06
		copy(frame[14:], arp)
		frames = append(frames, frame)
	}

	path, err := writePCAPFile(runID, "arp_sweep", frames, defaultDuration)
	logInfo("Return from PCAPARPSweep frames=%d path=%s", len(frames), path)
	return path, err
}

// buildARPRequest builds a 28-byte ARP request payload.
func buildARPRequest(srcMAC [6]byte, senderIP, targetIP string) []byte {
	buf := make([]byte, 28)
	buf[0] = 0x00
	buf[1] = 0x01 // Hardware type: Ethernet
	buf[2] = 0x08
	buf[3] = 0x00 // Protocol type: IPv4
	buf[4] = 0x06 // Hardware address length
	buf[5] = 0x04 // Protocol address length
	buf[6] = 0x00
	buf[7] = 0x01 // Operation: request
	copy(buf[8:14], srcMAC[:])
	binary.BigEndian.PutUint32(buf[14:18], ipToUint32(senderIP))
	// Target MAC: all zeros (unknown)
	binary.BigEndian.PutUint32(buf[24:28], ipToUint32(targetIP))
	return buf
}

func buildARPReply(srcMAC, targetMAC [6]byte, senderIP, targetIP string) []byte {
	buf := make([]byte, 28)
	buf[0] = 0x00
	buf[1] = 0x01 // Hardware type: Ethernet
	buf[2] = 0x08
	buf[3] = 0x00 // Protocol type: IPv4
	buf[4] = 0x06 // Hardware address length
	buf[5] = 0x04 // Protocol address length
	buf[6] = 0x00
	buf[7] = 0x02 // Operation: request
	copy(buf[8:14], targetMAC[:])
	binary.BigEndian.PutUint32(buf[14:18], ipToUint32(senderIP))
	copy(buf[18:24], srcMAC[:]) // Target MAC
	binary.BigEndian.PutUint32(buf[24:28], ipToUint32(targetIP))
	return buf
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// rdpClientPDU / smbNegotiatePDU referenced from packet_sender.go

// splitDomain splits a domain name into labels.
func splitDomain(domain string) []string {
	var parts []string
	current := ""
	for _, ch := range domain {
		if ch == '.' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
