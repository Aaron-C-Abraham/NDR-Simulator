// Package main — pcap_writer.go
// Writes captured packets to PCAP files (libpcap format) for PCAP-capable devices.
package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
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
	return writePCAPFileLinkType(runID, attackName, packets, duration, 1) // 1 = LINKTYPE_ETHERNET
}

// writePCAPFileLinkType is writePCAPFile with an explicit libpcap LINKTYPE_*
// value, for frame types other than Ethernet (e.g. 105 = LINKTYPE_IEEE802_11
// for raw 802.11 management frames used by wireless attacks).
func writePCAPFileLinkType(runID, attackName string, packets [][]byte, duration uint64, linkType uint32) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering writePCAPFileLinkType runID=%s attack=%s packets=%d linkType=%d", runID, attackName, len(packets), linkType)

	filename := fmt.Sprintf("%s_%s_%s_%06d.pcap", runID, attackName, time.Now().Format("20060102_150405"), time.Now().Nanosecond()/1000)
	path := filepath.Join(GlobalPCAPDir, filename)

	GlobalPCAPWriteLock.Lock()
	defer GlobalPCAPWriteLock.Unlock()

	file, err := os.Create(path)
	if err != nil {
		logError("writePCAPFileLinkType create %s: %v", path, err)
		return "", err
	}
	defer file.Close()

	ghdr := PCAPGlobalHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      65535,
		Network:      linkType,
	}
	if err = binary.Write(file, binary.LittleEndian, ghdr); err != nil {
		logError("writePCAPFileLinkType global header: %v", err)
		return "", err
	}

	for _, pkt := range packets {
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
			logError("writePCAPFileLinkType record header: %v", err)
			return "", err
		}
		if _, err = file.Write(pkt); err != nil {
			logError("writePCAPFileLinkType packet data: %v", err)
			return "", err
		}
	}

	logInfo("Return from writePCAPFileLinkType path=%s", path)
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
func buildEthernetFrameARP(srcMAC, dstMAC [6]byte, arpPayload []byte, protocol uint16) []byte {
	frame := make([]byte, 14+len(arpPayload))
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], protocol)
	copy(frame[14:], arpPayload)
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

// buildICMPSegment builds an ICMP segment with a correctly computed
// checksum. The checksum parameter is no longer used as input — Wireshark
// flags a literal 0x0000 checksum as "Bad checksum", so we always compute
// the real one here instead of trusting callers to pass a precomputed value.
func buildICMPSegment(PacketType, Code byte, _ uint16, identifier, seq uint16, payload []byte) []byte {
	seg := make([]byte, 8+len(payload))
	seg[0] = PacketType
	seg[1] = Code
	binary.BigEndian.PutUint16(seg[2:], 0) // checksum placeholder, filled below
	binary.BigEndian.PutUint16(seg[4:], identifier)
	binary.BigEndian.PutUint16(seg[6:], seq)
	copy(seg[8:], payload)

	checksum := icmpChecksum(seg)
	binary.BigEndian.PutUint16(seg[2:], checksum)
	return seg
}

// icmpChecksum computes the standard Internet checksum (RFC 1071) over an
// ICMP message, treating the checksum field itself as zero during
// calculation.
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
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
	bgFrames := generateBackgroundTrafficN(getAllDevices(), len(frames)/3)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile("scan", "portscan", finalFrames, defaultDuration)
	logInfo("Return from PCAPPortScan frames=%d path=%s", len(finalFrames), path)
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

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile("beacon", "beaconing", finalFrames, defaultDuration)
	logInfo("Return from PCAPBeaconing frames=%d path=%s", len(finalFrames), path)
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

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile("dnstunn", "dns_tunnel", finalFrames, defaultDuration)
	logInfo("Return from PCAPDNSTunnel frames=%d path=%s", len(finalFrames), path)
	return nil, path, err
}

// buildDNSQuery builds a minimal DNS query packet for a given domain,
// defaulting to QTYPE=TXT (used by DNS tunneling/exfil callers).
func buildDNSQuery(domain string) []byte {
	return buildDNSQueryType(domain, 0x0010) // TXT
}

// buildDNSQueryType is buildDNSQuery with an explicit QTYPE (e.g. 0x0001
// for A records), for callers that need a realistic query type rather
// than the TXT default (DNS spoofing/poisoning should query A, not TXT).
func buildDNSQueryType(domain string, qtype uint16) []byte {
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
	buf = append(buf, 0x00) // null terminator
	buf = append(buf, byte(qtype>>8), byte(qtype&0xFF))
	buf = append(buf, 0x00, 0x01) // QCLASS = IN
	return buf
}

// ─── Additional PCAP generators (Option B) ───────────────────────────────────

// PCAPSYNFlood generates PCAP frames for a SYN flood from multiple spoofed
// sources. Most SYNs get no reply (the realistic SYN-flood symptom — the
// target's backlog queue fills and it stops responding), but a handful
// of early SYNs receive a SYN-ACK back, since a real target doesn't drop
// every single packet from the very first one; the backlog only fills
// up partway through the flood.
func PCAPSYNFlood(runID, targetIP string, targetPort uint16, sourceIPs []string, duration int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPSYNFlood target=%s port=%d sources=%d", targetIP, targetPort, len(sourceIPs))

	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	targetMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	var frames [][]byte

	// Respond to roughly the first 10% of sources (or at least 1, if any
	// sources exist) before the simulated backlog "fills up" and the
	// target stops replying for the rest of the flood.
	replyCount := 1 // will be recalculated after scaling

	// Scale packet count with duration — repeat source IPs to simulate sustained flood
	pktsPerSrc := duration / 30
	if pktsPerSrc < 1 {
		pktsPerSrc = 1
	}
	var scaledSources []string
	for i := 0; i < pktsPerSrc; i++ {
		scaledSources = append(scaledSources, sourceIPs...)
	}
	replyCount = len(scaledSources) / 10
	if replyCount < 1 && len(scaledSources) > 0 {
		replyCount = 1
	}
	for idx, srcIP := range scaledSources {
		srcPort := randomPort()
		srcMAC := [6]byte{0x00, byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))}
		clientSeq := rand.Uint32()
		syn := buildTCPSegment(srcPort, targetPort, 0x02, clientSeq, 0, nil)
		ip := buildIPv4Packet(srcIP, targetIP, 6, syn)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))

		if idx < replyCount {
			serverSeq := rand.Uint32()
			synAck := buildTCPSegment(targetPort, srcPort, 0x12, serverSeq, clientSeq+1, nil)
			synAckIP := buildIPv4Packet(targetIP, srcIP, 6, synAck)
			frames = append(frames, buildEthernetFrame(targetMAC, srcMAC, synAckIP))
		}
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), len(frames)/3)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "syn_flood", finalFrames, defaultDuration)
	logInfo("Return from PCAPSYNFlood frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPUDPFlood generates PCAP frames for a UDP flood.
func PCAPUDPFlood(runID, targetIP string, targetPort uint16, sourceIPs []string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPUDPFlood target=%s port=%d sources=%d", targetIP, targetPort, len(sourceIPs))

	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	// Flood payload: when targetPort is 53 (DNS, the default for this
	// attack), Wireshark always tries to dissect the UDP payload as DNS.
	// A 12-byte valid-but-meaningless DNS header (QDCOUNT=0, all other
	// counts=0, no question/answer sections) followed by junk filler
	// parses cleanly as an empty DNS query instead of throwing
	// [Malformed Packet] — this is what real-world UDP/DNS flood tools'
	// garbage traffic looks like on the wire when captured.
	payload := make([]byte, 512)
	binary.BigEndian.PutUint16(payload[0:2], uint16(rand.Intn(65536))) // Transaction ID
	payload[2] = 0x01                                                  // Flags: standard query
	payload[3] = 0x00
	// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT all left as 0x0000 (zeroed)
	for i := 12; i < len(payload); i++ {
		payload[i] = 0x41 // filler after the valid header
	}
	var frames [][]byte
	for _, srcIP := range sourceIPs {
		srcMAC := [6]byte{0x00, byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))}
		udp := buildUDPDatagram(randomPort(), targetPort, payload)
		ip := buildIPv4Packet(srcIP, targetIP, 17, udp)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), len(frames)/3)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "udp_flood", finalFrames, defaultDuration)
	logInfo("Return from PCAPUDPFlood frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPHTTPFlood generates PCAP frames for a Layer-7 HTTP flood. A handful
// of early requests get a real HTTP response back (mostly 503 Service
// Unavailable, since the server is being hammered) before it's considered
// overwhelmed and stops responding for the rest of the flood — a real
// server doesn't go silent on request #1.
func PCAPHTTPFlood(runID, attackerIP, targetIP string, targetPort uint16, count int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPHTTPFlood attacker=%s target=%s port=%d count=%d", attackerIP, targetIP, targetPort, count)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x44}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	targetMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}

	// Respond to roughly the first 10% of requests before the server is
	// considered overwhelmed and stops replying for the rest.
	replyCount := count / 10
	if replyCount < 1 && count > 0 {
		replyCount = 1
	}

	var frames [][]byte
	for idx := 0; idx < count; idx++ {
		srcPort := randomPort()
		clientSeq := rand.Uint32()
		serverSeq := rand.Uint32()

		// TCP SYN
		syn := buildTCPSegment(srcPort, targetPort, 0x02, clientSeq, 0, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
		clientSeq++

		if idx < replyCount {
			// Server still responding — full handshake + request + response
			synAck := buildTCPSegment(targetPort, srcPort, 0x12, serverSeq, clientSeq, nil)
			frames = append(frames, buildEthernetFrame(targetMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
			serverSeq++

			ack := buildTCPSegment(srcPort, targetPort, 0x10, clientSeq, serverSeq, nil)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

			payload := []byte(fmt.Sprintf(
				"GET /?r=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
				randomHexString(8), targetIP))
			req := buildTCPSegment(srcPort, targetPort, 0x18, clientSeq, serverSeq, payload)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, req)))
			clientSeq += uint32(len(payload))

			respBody := []byte("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			resp := buildTCPSegment(targetPort, srcPort, 0x18, serverSeq, clientSeq, respBody)
			frames = append(frames, buildEthernetFrame(targetMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, resp)))
			serverSeq += uint32(len(respBody))

			// FIN from server closing connection after 503
			fin := buildTCPSegment(targetPort, srcPort, 0x11, serverSeq, clientSeq, nil)
			frames = append(frames, buildEthernetFrame(targetMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, fin)))
		} else {
			// Server overwhelmed — SYN goes unanswered, attacker keeps flooding
			payload := []byte(fmt.Sprintf(
				"GET /?r=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
				randomHexString(8), targetIP))
			req := buildTCPSegment(srcPort, targetPort, 0x18, clientSeq, serverSeq, payload)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, req)))
		}
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), len(frames)/3)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "http_flood", finalFrames, defaultDuration)
	logInfo("Return from PCAPHTTPFlood frames=%d path=%s", len(finalFrames), path)
	return path, err
}

func PCAPSlowloris(runID, attackerIP, targetIP string, connections int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPSlowloris attacker=%s target=%s connections=%d", attackerIP, targetIP, connections)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x55}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	var frames [][]byte

	for idx := 0; idx < connections; idx++ {
		srcPort := randomPort()
		clientSeq := rand.Uint32()
		serverSeq := rand.Uint32()

		// SYN
		syn := buildTCPSegment(srcPort, 80, 0x02, clientSeq, 0, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
		clientSeq++

		// SYN-ACK from server (server accepts the connection)
		synAck := buildTCPSegment(80, srcPort, 0x12, serverSeq, clientSeq, nil)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
		serverSeq++

		// ACK completing handshake
		ack := buildTCPSegment(srcPort, 80, 0x10, clientSeq, serverSeq, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

		// Partial HTTP header — never a complete request, intentionally missing final \r\n
		partial := []byte(fmt.Sprintf("GET /?%s HTTP/1.1\r\nHost: %s\r\n", randomHexString(8), targetIP))
		psh := buildTCPSegment(srcPort, 80, 0x18, clientSeq, serverSeq, partial)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, psh)))
		clientSeq += uint32(len(partial))

		// Keep-alive header drip — slow trickle to keep connection open
		drip := []byte("X-a: b\r\n")
		drip2 := buildTCPSegment(srcPort, 80, 0x18, clientSeq, serverSeq, drip)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, drip2)))
		clientSeq += uint32(len(drip))

		// Second drip to show the slow trickle pattern
		drip3 := buildTCPSegment(srcPort, 80, 0x18, clientSeq, serverSeq, drip)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, drip3)))
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), len(frames)/3)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "slowloris", finalFrames, defaultDuration)
	logInfo("Return from PCAPSlowloris frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// bruteForceExchange describes one protocol's wire-level shape for
// PCAPBruteForce: a request the client sends after the handshake (given
// the attempt index and the username list, so payloads can rotate through
// real per-attempt usernames matching what the calling attack's syslog
// messages claim was tried), and the server's rejection response carried
// in the data segment immediately before the RST.
type bruteForceExchange struct {
	clientPayload func(attempt int, usernames []string) []byte
	serverPayload func(attempt int, usernames []string) []byte
}

// bruteForceUsername returns usernames[attempt % len(usernames)], or a
// generic fallback if usernames is empty (callers that don't have a
// per-attempt username list, e.g. ssh/rdp/smb).
func bruteForceUsername(attempt int, usernames []string) string {
	if len(usernames) == 0 {
		return "admin"
	}
	return usernames[attempt%len(usernames)]
}

func bruteForceExchangeFor(protocol string) bruteForceExchange {
	switch protocol {
	case "ssh":
		return bruteForceExchange{
			clientPayload: func(int, []string) []byte { return []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n") },
			serverPayload: func(int, []string) []byte { return []byte("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\r\n") },
		}
	case "rdp":
		return bruteForceExchange{
			clientPayload: func(int, []string) []byte { return rdpClientPDU[:] },
			serverPayload: func(int, []string) []byte { return []byte{0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80, 0x02} },
		}
	case "smb":
		return bruteForceExchange{
			clientPayload: func(int, []string) []byte { return smbNegotiatePDU[:] },
			serverPayload: func(int, []string) []byte { return SMB2_Negotiate_Response },
		}
	case "ftp":
		return bruteForceExchange{
			clientPayload: func(attempt int, usernames []string) []byte {
				return []byte(fmt.Sprintf("USER %s\r\n", bruteForceUsername(attempt, usernames)))
			},
			serverPayload: func(int, []string) []byte { return []byte("530 Login incorrect.\r\n") },
		}
	case "telnet":
		return bruteForceExchange{
			clientPayload: func(attempt int, usernames []string) []byte {
				return []byte(bruteForceUsername(attempt, usernames) + "\r\n")
			},
			serverPayload: func(int, []string) []byte { return []byte("Login incorrect\r\n\r\nUsername: ") },
		}
	case "smtp":
		return bruteForceExchange{
			clientPayload: func(attempt int, usernames []string) []byte {
				// AUTH LOGIN exchanges base64 the username/password separately
				// in real SMTP; this is a simplified single-line stand-in
				// carrying the attempted username for traceability.
				return []byte(fmt.Sprintf("AUTH LOGIN\r\n%s\r\n", bruteForceUsername(attempt, usernames)))
			},
			serverPayload: func(int, []string) []byte { return []byte("535 5.7.8 Authentication failed\r\n") },
		}
	case "winrm":
		return bruteForceExchange{
			clientPayload: func(attempt int, usernames []string) []byte {
				return []byte(fmt.Sprintf("POST /wsman HTTP/1.1\r\nAuthorization: Basic %s\r\n\r\n", bruteForceUsername(attempt, usernames)))
			},
			serverPayload: func(int, []string) []byte {
				return []byte("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n")
			},
		}
	case "vnc":
		return bruteForceExchange{
			clientPayload: func(int, []string) []byte { return []byte{0x03, 0x00, 0x8a, 0x9c, 0xf1, 0x02, 0x44, 0x91} },
			serverPayload: func(int, []string) []byte { return []byte{0x00, 0x00, 0x00, 0x01} },
		}
	default:
		return bruteForceExchange{
			clientPayload: func(attempt int, usernames []string) []byte {
				return []byte(fmt.Sprintf("USER %s\r\nPASS %s\r\n", bruteForceUsername(attempt, usernames), randomHexString(8)))
			},
			serverPayload: func(int, []string) []byte { return nil },
		}
	}
}

// PCAPBruteForce generates PCAP frames for a login brute-force attack.
// protocol: "ssh", "rdp", "smb", "ftp", "telnet", "smtp", "winrm", or "vnc".
// usernames, if non-empty, is rotated through per attempt (attempt %
// len(usernames)) so the PCAP payload matches the same username sequence
// the calling attack's syslog messages report attempting; pass nil for
// protocols without a meaningful per-attempt username (ssh/rdp/smb).
// Each attempt gets its own complete three-way handshake (SYN, SYN/ACK,
// ACK — previously the ACK was missing), then a protocol-appropriate client
// payload, a server rejection payload, and a final RST/ACK that correctly
// acks the data sent so far rather than a bare zeroed RST.
func PCAPBruteForce(runID, attackerIP, targetIP string, targetPort uint16, protocol string, attempts int, usernames []string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPBruteForce attacker=%s target=%s proto=%s attempts=%d", attackerIP, targetIP, protocol, attempts)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, 0x66}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	exchange := bruteForceExchangeFor(protocol)
	var frames [][]byte

	for idx := 0; idx < attempts; idx++ {
		srcPort := randomPort()
		clientSeq := rand.Uint32()
		serverSeq := rand.Uint32()

		// SYN
		syn := buildTCPSegment(srcPort, targetPort, 0x02, clientSeq, 0, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
		clientSeq++

		// SYN-ACK
		synAck := buildTCPSegment(targetPort, srcPort, 0x12, serverSeq, clientSeq, nil)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
		serverSeq++

		// ACK — completes the handshake (this was missing before)
		ack := buildTCPSegment(srcPort, targetPort, 0x10, clientSeq, serverSeq, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

		// Client payload (credentials / auth attempt)
		clientPayload := exchange.clientPayload(idx, usernames)
		if len(clientPayload) > 0 {
			data := buildTCPSegment(srcPort, targetPort, 0x18, clientSeq, serverSeq, clientPayload)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, data)))
			clientSeq += uint32(len(clientPayload))

			// ACK the client payload
			dataAck := buildTCPSegment(targetPort, srcPort, 0x10, serverSeq, clientSeq, nil)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, dataAck)))
		}

		// Server rejection payload (auth failure message)
		serverPayload := exchange.serverPayload(idx, usernames)
		if len(serverPayload) > 0 {
			resp := buildTCPSegment(targetPort, srcPort, 0x18, serverSeq, clientSeq, serverPayload)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, resp)))
			serverSeq += uint32(len(serverPayload))
		}

		// RST/ACK (auth failure → connection torn down)
		rst := buildTCPSegment(targetPort, srcPort, 0x14, serverSeq, clientSeq, nil)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, rst)))
	}

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "bruteforce_", finalFrames, defaultDuration)
	logInfo("Return from PCAPBruteforce frames=%d path=%s", len(finalFrames), path)
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

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "exfil_http", finalFrames, defaultDuration)
	logInfo("Return from PCAPExfil frames=%d path=%s", len(finalFrames), path)
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

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "lateral_smb", finalFrames, defaultDuration)
	logInfo("Return from PCAPLateral frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPARPSweep generates PCAP frames for an ARP broadcast sweep.
func PCAPARPSweep(runID, attackerIP string, subnet string, count int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPARPSweep attacker=%s subnet=%s count=%d", attackerIP, subnet, count)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	broadcastMAC := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	var frames [][]byte

	parts := strings.Split(subnet, ".")
	prefix := "10.0.1"
	if len(parts) >= 3 {
		prefix = parts[0] + "." + parts[1] + "." + parts[2]
	}

	for idx := 1; idx <= count; idx++ {
		targetIP := fmt.Sprintf("%s.%d", prefix, idx)

		// Build ARP request payload (28 bytes)
		arpReq := buildARPRequest(srcMAC, attackerIP, targetIP)

		// Build complete Ethernet + ARP frame
		frame := make([]byte, 14+len(arpReq))
		copy(frame[0:6], broadcastMAC[:])                // Destination MAC (broadcast)
		copy(frame[6:12], srcMAC[:])                     // Source MAC
		binary.BigEndian.PutUint16(frame[12:14], 0x0806) // EtherType: ARP
		copy(frame[14:], arpReq)                         // ARP payload

		frames = append(frames, frame)
	}

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "arp_scan", finalFrames, defaultDuration)
	logInfo("Return from PCAPARPSweep frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// buildARPRequest builds a 28-byte ARP request payload.
func buildARPRequest(srcMAC [6]byte, senderIP, targetIP string) []byte {
	buf := make([]byte, 28)
	binary.BigEndian.PutUint16(buf[0:2], 0x0001)  // Hardware type: Ethernet
	binary.BigEndian.PutUint16(buf[2:4], 0x0800)  // Protocol type: IPv4
	buf[4] = 6                                    // Hardware address length
	buf[5] = 4                                    // Protocol address length
	binary.BigEndian.PutUint16(buf[6:8], 0x0001)  // Operation: request
	copy(buf[8:14], srcMAC[:])                    // Sender hardware address
	copy(buf[14:18], net.ParseIP(senderIP).To4()) // Sender protocol address
	// Target hardware address (bytes 18:24) = zeros (unknown in request)
	copy(buf[24:28], net.ParseIP(targetIP).To4()) // Target protocol address
	return buf
}

func buildARPReply(srcMAC, targetMAC [6]byte, senderIP, targetIP string) []byte {
	buf := make([]byte, 28)
	binary.BigEndian.PutUint16(buf[0:2], 0x0001)  // Hardware type: Ethernet
	binary.BigEndian.PutUint16(buf[2:4], 0x0800)  // Protocol type: IPv4
	buf[4] = 6                                    // Hardware address length
	buf[5] = 4                                    // Protocol address length
	binary.BigEndian.PutUint16(buf[6:8], 0x0002)  // Operation: reply
	copy(buf[8:14], srcMAC[:])                    // Sender hardware address
	copy(buf[14:18], net.ParseIP(senderIP).To4()) // Sender protocol address
	copy(buf[18:24], targetMAC[:])                // Target hardware address
	copy(buf[24:28], net.ParseIP(targetIP).To4()) // Target protocol address
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

// ─── Additional PCAP generators (gap-fill pass) ──────────────────────────────

// PCAPGenericTCPExchange generates a minimal SYN → request → response PCAP
// for attacks that have a real but simple request/response shape (SQLi,
// command injection, XSS, LDAP injection, credential stuffing, Kerberoasting,
// pass-the-hash) where we don't have a protocol-specific byte-level builder.
// The payloads are plain text approximations of the actual wire format, not
// byte-accurate protocol implementations — good enough to show a request/
// response pair on the right port, not a parseable protocol capture.
func PCAPGenericTCPExchange(runID, attackName, attackerIP, targetIP string, targetPort uint16, requestPayload, responsePayload []byte) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPGenericTCPExchange attack=%s attacker=%s target=%s port=%d", attackName, attackerIP, targetIP, targetPort)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	seq := rand.Uint32()

	var frames [][]byte
	syn := buildTCPSegment(srcPort, targetPort, 0x02, seq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))

	synAck := buildTCPSegment(targetPort, srcPort, 0x12, 0, seq+1, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))

	ack := buildTCPSegment(srcPort, targetPort, 0x10, seq+1, 1, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

	if len(requestPayload) > 0 {
		req := buildTCPSegment(srcPort, targetPort, 0x18, seq+1, 1, requestPayload)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, req)))
	}
	if len(responsePayload) > 0 {
		resp := buildTCPSegment(targetPort, srcPort, 0x18, 1, seq+uint32(1+len(requestPayload)), responsePayload)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, resp)))
	}

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, attackName, finalFrames, defaultDuration)
	logInfo("Return from PCAPGenericTCPExchange frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPDNSQueryResponse generates DNS query/response pairs.
// For DGA (nxdomain=true): single query + NXDOMAIN response.
// For DNS cache poisoning (nxdomain=false): single query + multiple forged
// responses from attacker with different source ports and TXIDs, simulating
// a Kaminsky-style cache poisoning attack. One response is finally accepted.
func PCAPDNSQueryResponse(runID, attackName, clientIP, dnsIP string, domain string, nxdomain bool) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPDNSQueryResponse attack=%s client=%s dns=%s domain=%s", attackName, clientIP, dnsIP, domain)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	attackerMAC := [6]byte{0x00, 0xBB, 0x22, 0x33, 0x44, byte(rand.Intn(255))}

	if nxdomain {
		// DGA case: single query + NXDOMAIN response
		srcPort := randomPort()
		query := buildDNSQueryType(domain, 0x0010) // TXT
		queryFrame := buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(clientIP, dnsIP, 17, buildUDPDatagram(srcPort, 53, query)))

		response := make([]byte, len(query))
		copy(response, query)
		response[2] = 0x81
		response[3] = 0x83 // RCODE=3 NXDOMAIN
		responseFrame := buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dnsIP, clientIP, 17, buildUDPDatagram(53, srcPort, response)))
		frames := [][]byte{queryFrame, responseFrame}
		bgFrames := generateBackgroundTraffic(getAllDevices())
		finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
		path, err := writePCAPFile(runID, attackName, finalFrames, defaultDuration)
		logInfo("Return from PCAPDNSQueryResponse frames=%d path=%s", len(finalFrames), path)
		return path, err
	}

	// DNS Cache Poisoning case (Kaminsky-style):
	var frames [][]byte

	resolverPort := randomPort()
	txid := uint16(rand.Intn(65536))

	// Build question section once — reused in all responses
	parts := splitDomain(domain)
	var questionSection []byte
	for _, part := range parts {
		questionSection = append(questionSection, byte(len(part)))
		questionSection = append(questionSection, []byte(part)...)
	}
	questionSection = append(questionSection, 0x00)       // null terminator
	questionSection = append(questionSection, 0x00, 0x01) // QTYPE A
	questionSection = append(questionSection, 0x00, 0x01) // QCLASS IN

	// Forged answer: 198.51.100.1
	forgedAnswerSection := []byte{
		0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
		0xC6, 0x33, 0x64, 0x01,
	}

	// Real answer: 8.8.8.8
	realAnswerSection := []byte{
		0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
		0x08, 0x08, 0x08, 0x08,
	}

	buildDNSResponse := func(id uint16, answer []byte) []byte {
		var buf []byte
		buf = append(buf, byte(id>>8), byte(id&0xFF))
		buf = append(buf, 0x81, 0x80)
		buf = append(buf, 0x00, 0x01)
		buf = append(buf, 0x00, 0x01)
		buf = append(buf, 0x00, 0x00)
		buf = append(buf, 0x00, 0x00)
		buf = append(buf, questionSection...)
		buf = append(buf, answer...)
		return buf
	}

	// Frame 1: Resolver queries upstream DNS
	query := buildDNSQueryType(domain, 0x0001)
	binary.BigEndian.PutUint16(query[0:2], txid)
	queryFrame := buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(clientIP, dnsIP, 17, buildUDPDatagram(resolverPort, 53, query)))
	frames = append(frames, queryFrame)

	// Frames 2-11: Attacker floods wrong TXIDs from different source ports
	for i := 0; i < 10; i++ {
		wrongTXID := uint16(rand.Intn(65536))
		forgedResponse := buildDNSResponse(wrongTXID, forgedAnswerSection)
		attackerSrcPort := randomPort()
		forgedFrame := buildEthernetFrame(attackerMAC, srcMAC, buildIPv4Packet("198.51.100.1", clientIP, 17, buildUDPDatagram(attackerSrcPort, resolverPort, forgedResponse)))
		frames = append(frames, forgedFrame)
	}

	// Frame 12: Winning forged response — correct TXID, accepted by resolver
	winningResponse := buildDNSResponse(txid, forgedAnswerSection)
	winningFrame := buildEthernetFrame(attackerMAC, srcMAC, buildIPv4Packet("198.51.100.1", clientIP, 17, buildUDPDatagram(randomPort(), resolverPort, winningResponse)))
	frames = append(frames, winningFrame)

	// Frame 13: Legitimate response arrives too late — ignored
	legitResponse := buildDNSResponse(txid, realAnswerSection)
	legitFrame := buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dnsIP, clientIP, 17, buildUDPDatagram(53, resolverPort, legitResponse)))
	frames = append(frames, legitFrame)

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, attackName, finalFrames, defaultDuration)
	logInfo("Return from PCAPDNSQueryResponse frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAP80211Beacon generates a minimal raw 802.11 Beacon management frame
// (used for rogue AP detection). Uses LINKTYPE_IEEE802_11 (105), not
// Ethernet — this is genuinely a different link layer, so it must go
// through writePCAPFileLinkType rather than writePCAPFile.
func PCAP80211Beacon(runID, attackName string, apMAC [6]byte, ssid string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAP80211Beacon ssid=%s", ssid)

	broadcastMAC := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	frame := build80211Beacon(apMAC, broadcastMAC, ssid)
	path, err := writePCAPFileLinkType(runID, attackName, [][]byte{frame}, defaultDuration, 105)
	logInfo("Return from PCAP80211Beacon path=%s", path)
	return path, err
}

// PCAP80211Deauth generates a minimal raw 802.11 Deauthentication management
// frame (used for deauth flood attacks). Same LINKTYPE_IEEE802_11 caveat
// as PCAP80211Beacon.
func PCAP80211Deauth(runID, attackName string, apMAC, clientMAC [6]byte, count int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAP80211Deauth count=%d", count)

	var frames [][]byte
	for idx := 0; idx < count; idx++ {
		frames = append(frames, build80211Deauth(apMAC, clientMAC))
	}
	path, err := writePCAPFileLinkType(runID, attackName, frames, defaultDuration, 105)
	logInfo("Return from PCAP80211Deauth frames=%d path=%s", len(frames), path)
	return path, err
}

// build80211Beacon builds a minimal 802.11 Beacon frame: 24-byte MAC header
// (frame control, duration, addr1/2/3, seq) followed by a fixed-length
// timestamp/interval/capability block and an SSID information element.
// This is a simplified, non-RFC-exhaustive beacon — enough to identify as
// a Beacon frame type/subtype with the right SSID in a packet analyzer, not
// a full 802.11 standard-compliant frame (no rate sets, no other IEs).
func build80211Beacon(apMAC, dstMAC [6]byte, ssid string) []byte {
	hdr := make([]byte, 24)
	hdr[0] = 0x80 // Type/Subtype: Management/Beacon
	hdr[1] = 0x00
	copy(hdr[4:10], dstMAC[:])
	copy(hdr[10:16], apMAC[:])
	copy(hdr[16:22], apMAC[:]) // BSSID = AP MAC

	fixed := make([]byte, 12)
	binary.LittleEndian.PutUint64(fixed[0:8], uint64(time.Now().UnixMicro()))
	binary.LittleEndian.PutUint16(fixed[8:10], 100)     // beacon interval
	binary.LittleEndian.PutUint16(fixed[10:12], 0x0411) // capability info: ESS + privacy

	ssidIE := append([]byte{0x00, byte(len(ssid))}, []byte(ssid)...)

	frame := append(hdr, fixed...)
	frame = append(frame, ssidIE...)
	return frame
}

// build80211Deauth builds a minimal 802.11 Deauthentication frame: 24-byte
// MAC header plus a 2-byte reason code.
func build80211Deauth(apMAC, clientMAC [6]byte) []byte {
	hdr := make([]byte, 24)
	hdr[0] = 0xC0 // Type/Subtype: Management/Deauthentication
	hdr[1] = 0x00
	copy(hdr[4:10], clientMAC[:])
	copy(hdr[10:16], apMAC[:])
	copy(hdr[16:22], apMAC[:])

	reasonCode := []byte{0x07, 0x00} // Reason: Class 3 frame received from nonassociated station
	return append(hdr, reasonCode...)
}

// buildIPv4PacketFragment builds an IPv4 packet with explicit fragmentation
// fields, for attacks that need real fragment semantics (MF flag, fragment
// offset, shared IP ID across fragments) rather than buildIPv4Packet's
// always-unfragmented defaults.
func buildIPv4PacketFragment(srcIP, dstIP string, protocol uint8, id uint16, moreFragments bool, fragOffsetBytes int, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:], id)
	flagsAndOffset := uint16(fragOffsetBytes / 8)
	if moreFragments {
		flagsAndOffset |= 0x2000 // MF bit
	}
	binary.BigEndian.PutUint16(pkt[6:], flagsAndOffset)
	pkt[8] = 64
	pkt[9] = protocol
	binary.BigEndian.PutUint32(pkt[12:], ipToUint32(srcIP))
	binary.BigEndian.PutUint32(pkt[16:], ipToUint32(dstIP))
	copy(pkt[20:], payload)
	checksum := ipChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:], checksum)
	return pkt
}

// PCAPIPFragmentation generates a fragmented IP packet stream: a single
// upper-layer payload (a TCP segment with data) split across multiple IP
// fragments per fragSize, only the first fragment carrying the TCP header.
func PCAPIPFragmentation(runID, attackerIP, targetIP string, targetPort uint16, fragSize int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPIPFragmentation attacker=%s target=%s fragSize=%d", attackerIP, targetIP, fragSize)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()

	tcpPayload := []byte("GET /scan-probe-evasion-payload HTTP/1.1\r\nHost: target\r\nX-Pad: " +
		strings.Repeat("A", 40) + "\r\n\r\n")
	fullSegment := buildTCPSegment(srcPort, targetPort, 0x18, rand.Uint32(), 0, tcpPayload)

	id := uint16(rand.Intn(65535))
	var frames [][]byte
	for offset := 0; offset < len(fullSegment); offset += fragSize {
		end := offset + fragSize
		more := true
		if end >= len(fullSegment) {
			end = len(fullSegment)
			more = false
		}
		chunk := fullSegment[offset:end]
		ipFrag := buildIPv4PacketFragment(attackerIP, targetIP, 6, id, more, offset, chunk)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ipFrag))
	}

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "ip_fragmentation", finalFrames, defaultDuration)
	logInfo("Return from PCAPIPFragmentation frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// writeICMPTunnelPCAP generates an ICMP echo request/reply pair carrying an
// oversized payload, representing ICMP-based C2 tunneling.
func writeICMPTunnelPCAP(runID, attackerIP, c2IP string) (string, error) {
	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	payload := make([]byte, 256)
	rand.Read(payload)
	identifier := uint16(rand.Intn(65535))

	echoReq := buildICMPSegment(8, 0, 0, identifier, 1, payload)
	reqFrame := buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, c2IP, 1, echoReq))

	echoReply := buildICMPSegment(0, 0, 0, identifier, 1, payload)
	replyFrame := buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(c2IP, attackerIP, 1, echoReply))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic([][]byte{reqFrame, replyFrame}, bgFrames)
	return writePCAPFile(runID, "protocol_tunnel_icmp", finalFrames, defaultDuration)
}

// PCAPICMPFlood generates a burst of ICMP echo requests representing a
// Smurf/ICMP flood. A handful of early echo requests get a real echo
// reply back — a real target doesn't go instantly unresponsive; it starts
// dropping/ignoring requests only once it's overwhelmed partway through
// the flood.
func PCAPICMPFlood(runID, attackerIP, targetIP string, count int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPICMPFlood attacker=%s target=%s count=%d", attackerIP, targetIP, count)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	targetMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}

	identifier := uint16(rand.Intn(65535))
	var frames [][]byte

	// Respond to roughly the first 10% of echo requests before the target
	// is considered overwhelmed and stops replying for the rest.
	replyCount := count / 10
	if replyCount < 1 && count > 0 {
		replyCount = 1
	}

	for idx := 0; idx < count; idx++ {
		seq := uint16(idx)
		echo := buildICMPSegment(8, 0, 0, identifier, seq, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 1, echo)))

		if idx < replyCount {
			echoReply := buildICMPSegment(0, 0, 0, identifier, seq, nil)
			frames = append(frames, buildEthernetFrame(targetMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 1, echoReply)))
		}
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), len(frames)/3)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "icmp_flood", finalFrames, defaultDuration)
	logInfo("Return from PCAPICMPFlood frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPUDPAmplification generates the correct Memcached/UDP amplification
// pattern: a small spoofed request appearing to come from the victim
// (src=victimIP, dst=reflectorIP, dport=11211), followed by a large
// amplified response back to the victim (src=reflectorIP, dst=victimIP).
// The attacker's real IP never appears — only the spoofed victim src does.
func PCAPUDPAmplification(runID, reflectorIP, victimIP string, reflectorPort uint16, responsePayloadSize int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPUDPAmplification reflector=%s victim=%s port=%d", reflectorIP, victimIP, reflectorPort)

	reflectorMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	victimMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	gatewayMAC := [6]byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01}

	var frames [][]byte
	victimEphemeral := randomPort()

	// Memcached stats request payload — "stats\r\n" is the canonical trigger
	// for large amplification responses from open Memcached servers.
	memcachedRequest := []byte("stats\r\n")

	// Repeat the amplification pattern multiple times to show the flood
	for i := 0; i < 20; i++ {
		// --- Spoofed request: appears to come FROM victim TO reflector ---
		// Attacker sends this with victim's IP as source (IP spoofing).
		// Wireshark shows: victimIP:ephemeral → reflectorIP:11211
		reqUDP := buildUDPDatagram(victimEphemeral, reflectorPort, memcachedRequest)
		reqFrame := buildEthernetFrame(victimMAC, gatewayMAC,
			buildIPv4Packet(victimIP, reflectorIP, 17, reqUDP))
		frames = append(frames, reqFrame)

		// --- Amplified response: reflector blasts large payload TO victim ---
		// This is the damage: ~1400 bytes back for 7 bytes in (~200x factor).
		// Wireshark shows: reflectorIP:11211 → victimIP:ephemeral
		respPayload := make([]byte, responsePayloadSize)
		rand.Read(respPayload)
		respUDP := buildUDPDatagram(reflectorPort, victimEphemeral, respPayload)
		respFrame := buildEthernetFrame(reflectorMAC, victimMAC,
			buildIPv4Packet(reflectorIP, victimIP, 17, respUDP))
		frames = append(frames, respFrame)
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), 15)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "memcached_amplification", finalFrames, defaultDuration)
	logInfo("Return from PCAPUDPAmplification frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPACKFlood generates a sustained flood of bare ACK packets from spoofed
// sources. Each source IP sends multiple ACKs cycling through varying seq/ack
// numbers — no prior handshake — overwhelming the target's connection table.
func PCAPACKFlood(runID, targetIP string, targetPort uint16, sourceIPs []string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPACKFlood target=%s port=%d sources=%d", targetIP, targetPort, len(sourceIPs))

	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	var frames [][]byte

	// Pre-assign a stable ephemeral port and seq base per source so packets
	// look like they belong to an established (but never set up) session.
	type srcState struct {
		mac     [6]byte
		srcPort uint16
		seq     uint32
		ack     uint32
	}
	states := make([]srcState, len(sourceIPs))
	for i := range sourceIPs {
		states[i] = srcState{
			mac:     [6]byte{0x00, byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))},
			srcPort: randomPort(),
			seq:     rand.Uint32(),
			ack:     rand.Uint32(),
		}
	}

	// 300 ACKs total — 10 packets per source for 30 sources.
	// Enough to show a clear flood pattern in Wireshark without
	// making the PCAP file unwieldy.
	acksPerSource := 10
	for round := 0; round < acksPerSource; round++ {
		for i, srcIP := range sourceIPs {
			s := &states[i]
			ackSeg := buildTCPSegment(s.srcPort, targetPort, 0x10, s.seq, s.ack, nil)
			frames = append(frames, buildEthernetFrame(s.mac, dstMAC,
				buildIPv4Packet(srcIP, targetIP, 6, ackSeg)))
			s.seq += uint32(rand.Intn(500) + 1) // advance seq to look like ongoing session
		}
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), 30)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "ack_flood", finalFrames, defaultDuration)
	logInfo("Return from PCAPACKFlood frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPRSTFlood generates a sustained flood of forged TCP RST packets targeting
// established-looking sessions. Uses varying spoofed source IPs and realistic
// seq numbers to show the session-teardown pattern in Wireshark.
func PCAPRSTFlood(runID, attackerIP, targetIP string, targetPort uint16, count int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPRSTFlood attacker=%s target=%s port=%d count=%d", attackerIP, targetIP, targetPort, count)

	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}

	// Generate a pool of spoofed attacker IPs derived from the base attacker IP.
	// RST floods are typically sent from many sources to bypass simple filters.
	baseOctets := [4]byte{}
	fmt.Sscanf(attackerIP, "%d.%d.%d.%d", &baseOctets[0], &baseOctets[1], &baseOctets[2], &baseOctets[3])
	spoofedSrcs := make([]string, 10)
	for i := range spoofedSrcs {
		spoofedSrcs[i] = fmt.Sprintf("%d.%d.%d.%d",
			baseOctets[0], baseOctets[1],
			rand.Intn(254)+1, rand.Intn(254)+1)
	}

	var frames [][]byte
	for idx := 0; idx < count; idx++ {
		srcIP := spoofedSrcs[idx%len(spoofedSrcs)]
		srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, byte(idx >> 8), byte(idx)}
		// RST with plausible seq — looks like it's resetting a real session
		rst := buildTCPSegment(randomPort(), targetPort, 0x04, rand.Uint32(), 0, nil)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC,
			buildIPv4Packet(srcIP, targetIP, 6, rst)))
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), count/10+10)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "rst_flood", finalFrames, defaultDuration)
	logInfo("Return from PCAPRSTFlood frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// buildMinimalTLSClientHello builds a structurally valid (if minimal) TLS
// ClientHello: record header, handshake header, client version, 32-byte
// random, zero-length session ID, one cipher suite, no compression,
// no extensions. Enough for Wireshark's TLS dissector to parse without
// throwing a malformed-packet error, unlike a truncated stub.
func buildMinimalTLSClientHello() []byte {
	random := make([]byte, 32)
	rand.Read(random)

	body := make([]byte, 0, 40)
	body = append(body, 0x03, 0x03) // client_version: TLS 1.2
	body = append(body, random...)  // 32-byte random
	body = append(body, 0x00)       // session_id length: 0
	body = append(body, 0x00, 0x02) // cipher_suites length: 2 bytes
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01)       // compression_methods length: 1
	body = append(body, 0x00)       // compression method: null
	body = append(body, 0x00, 0x00) // extensions length: 0

	handshake := make([]byte, 0, len(body)+4)
	handshake = append(handshake, 0x01)                                                     // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body))) // 3-byte length
	handshake = append(handshake, body...)

	record := make([]byte, 0, len(handshake)+5)
	record = append(record, 0x16, 0x03, 0x01) // Handshake, TLS 1.0 record version
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

// TCPOption represents a single TCP header option for OS-fingerprint-style
// probes. Kind follows RFC 793/1323/2018 option-kind numbers. Value is the
// raw argument bytes for options that take one (MSS, WScale, Timestamp);
// nil for options with no argument (NOP, EOL, SACK-permitted).
type TCPOption struct {
	Kind  byte
	Value []byte
}

const (
	tcpOptEOL       = 0
	tcpOptNOP       = 1
	tcpOptMSS       = 2
	tcpOptWScale    = 3
	tcpOptSACKPerm  = 4
	tcpOptTimestamp = 8
)

// NOP returns a single-byte No-Operation TCP option.
func NOP() TCPOption { return TCPOption{Kind: tcpOptNOP} }

// EOL returns the End-of-Options-List TCP option.
func EOL() TCPOption { return TCPOption{Kind: tcpOptEOL} }

// MSS returns a Maximum Segment Size option carrying the given 16-bit value.
func MSS(value uint16) TCPOption {
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, value)
	return TCPOption{Kind: tcpOptMSS, Value: v}
}

// WScale returns a Window Scale option carrying the given shift count.
func WScale(shift byte) TCPOption {
	return TCPOption{Kind: tcpOptWScale, Value: []byte{shift}}
}

// SACKPermitted returns a zero-length SACK-permitted option.
func SACKPermitted() TCPOption {
	return TCPOption{Kind: tcpOptSACKPerm}
}

// Timestamp returns a Timestamp option carrying TSval and TSecr (4 bytes each).
func Timestamp(tsval, tsecr uint32) TCPOption {
	v := make([]byte, 8)
	binary.BigEndian.PutUint32(v[0:4], tsval)
	binary.BigEndian.PutUint32(v[4:8], tsecr)
	return TCPOption{Kind: tcpOptTimestamp, Value: v}
}

// encodeTCPOptions serializes a list of TCPOptions into the wire format
// (kind byte, then for options with arguments: total-length byte, then the
// argument bytes), padded with trailing NOPs to the next multiple of 4 bytes
// so the resulting TCP header length stays a whole number of 32-bit words,
// as TCP requires (RFC 793 §3.1, Data Offset field).
func encodeTCPOptions(opts []TCPOption) []byte {
	var buf []byte
	for _, opt := range opts {
		switch opt.Kind {
		case tcpOptEOL, tcpOptNOP:
			buf = append(buf, opt.Kind)
		default:
			totalLen := byte(2 + len(opt.Value)) // kind byte + length byte + value
			buf = append(buf, opt.Kind, totalLen)
			buf = append(buf, opt.Value...)
		}
	}
	for len(buf)%4 != 0 {
		buf = append(buf, tcpOptNOP)
	}
	return buf
}

// buildTCPSegmentWithOptions is buildTCPSegment with TCP options support,
// for OS-fingerprint-style probes that need specific option combinations
// (MSS, window scale, timestamp, SACK-permitted, NOP, EOL) to be byte-exact
// to nmap's probe specification. The Data Offset field is computed from the
// actual encoded options length, since unlike buildTCPSegment (always a
// fixed 20-byte/5-word header), this header's length varies per probe.
func buildTCPSegmentWithOptions(srcPort, dstPort uint16, flags uint8, seq, ack uint32, window uint16, opts []TCPOption, payload []byte) []byte {
	optBytes := encodeTCPOptions(opts)
	headerLen := 20 + len(optBytes)
	dataOffset := byte(headerLen / 4)

	seg := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:], srcPort)
	binary.BigEndian.PutUint16(seg[2:], dstPort)
	binary.BigEndian.PutUint32(seg[4:], seq)
	binary.BigEndian.PutUint32(seg[8:], ack)
	seg[12] = dataOffset << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:], window)
	// seg[16:18] checksum left as 0, same convention as buildTCPSegment
	// seg[18:20] urgent pointer left as 0 by default
	copy(seg[20:], optBytes)
	copy(seg[20+len(optBytes):], payload)
	return seg
}

// buildSEQProbes builds the 6 TCP SYN probes nmap sends for SEQ/OPS/WIN/T1
// fingerprinting, per https://nmap.org/book/osdetect-methods.html. Each
// probe carries the exact documented TCP options and window value, uses its
// own source port (matching nmap's real behavior of 6 independent probes,
// not one persistent connection), and is sent 100ms apart. Each probe gets
// a SYN-ACK response and a closing ACK so Wireshark doesn't see overlapping
// connections on reused ports. Returns the full ordered frame list and the
// 6 sequence numbers used (for tests/inspection if needed).
func buildSEQProbes(srcIP, dstIP string, dstPort uint16, srcMAC, dstMAC [6]byte) (frames [][]byte, seqs []uint32) {
	type seqProbeSpec struct {
		opts   []TCPOption
		window uint16
	}
	specs := []seqProbeSpec{
		{[]TCPOption{WScale(10), NOP(), MSS(1460), Timestamp(0xFFFFFFFF, 0), SACKPermitted()}, 1},
		{[]TCPOption{MSS(1400), WScale(0), SACKPermitted(), Timestamp(0xFFFFFFFF, 0), EOL()}, 63},
		{[]TCPOption{Timestamp(0xFFFFFFFF, 0), NOP(), NOP(), WScale(5), NOP(), MSS(640)}, 4},
		{[]TCPOption{SACKPermitted(), Timestamp(0xFFFFFFFF, 0), WScale(10), EOL()}, 4},
		{[]TCPOption{MSS(536), SACKPermitted(), Timestamp(0xFFFFFFFF, 0), WScale(10), EOL()}, 16},
		{[]TCPOption{MSS(265), SACKPermitted(), Timestamp(0xFFFFFFFF, 0)}, 512},
	}

	for i, spec := range specs {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		srcPort := randomPort()
		seq := rand.Uint32()
		seqs = append(seqs, seq)

		probeSeg := buildTCPSegmentWithOptions(srcPort, dstPort, 0x02, seq, 0, spec.window, spec.opts, nil)
		probeIP := buildIPv4Packet(srcIP, dstIP, 6, probeSeg)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, probeIP))

		respSeq := rand.Uint32()
		respOpts := []TCPOption{MSS(1460), SACKPermitted(), Timestamp(0xFFFFFFFF, 0xFFFFFFFF), NOP(), WScale(7)}
		respSeg := buildTCPSegmentWithOptions(dstPort, srcPort, 0x12, respSeq, seq+1, 65535, respOpts, nil)
		respIP := buildIPv4Packet(dstIP, srcIP, 6, respSeg)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, respIP))

		ackSeg := buildTCPSegment(srcPort, dstPort, 0x10, seq+1, respSeq+1, nil)
		ackIP := buildIPv4Packet(srcIP, dstIP, 6, ackSeg)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ackIP))
	}
	return frames, seqs
}

// buildIPv4PacketWithTOSAndDF is buildIPv4Packet with explicit control over
// the TOS byte and the IP "Don't Fragment" bit, needed for nmap's IE (ICMP
// echo) OS-fingerprint probes, which specify both fields exactly.
func buildIPv4PacketWithTOSAndDF(srcIP, dstIP string, protocol uint8, tos byte, df bool, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = tos
	binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:], uint16(rand.Intn(65535)))
	flags := uint16(0)
	if df {
		flags = 0x4000 // DF bit
	}
	binary.BigEndian.PutUint16(pkt[6:], flags)
	pkt[8] = 64
	pkt[9] = protocol
	binary.BigEndian.PutUint32(pkt[12:], ipToUint32(srcIP))
	binary.BigEndian.PutUint32(pkt[16:], ipToUint32(dstIP))
	copy(pkt[20:], payload)
	checksum := ipChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:], checksum)
	return pkt
}

// buildIEProbes builds the 2 ICMP echo request probes nmap sends for the IE
// test, per https://nmap.org/book/osdetect-methods.html. Probe 1: DF set,
// TOS=0, code=9, seq=295, 120 bytes of 0x00. Probe 2: TOS=4, code=0, ID and
// seq incremented by 1, 150 bytes of 0x00. Includes plausible echo-reply
// responses (response behavior is not nmap-specified).
func buildIEProbes(srcIP, dstIP string, srcMAC, dstMAC [6]byte) (frames [][]byte) {
	identifier := uint16(rand.Intn(65535))
	seq1 := uint16(295)

	payload1 := make([]byte, 120)
	echo1 := buildICMPSegment(8, 9, 0, identifier, seq1, payload1)
	ip1 := buildIPv4PacketWithTOSAndDF(srcIP, dstIP, 1, 0x00, true, echo1)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip1))

	reply1 := buildICMPSegment(0, 0, 0, identifier, seq1, payload1)
	ipReply1 := buildIPv4PacketWithTOSAndDF(dstIP, srcIP, 1, 0x00, false, reply1)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, ipReply1))

	identifier2 := identifier + 1
	seq2 := seq1 + 1
	payload2 := make([]byte, 150)
	echo2 := buildICMPSegment(8, 0, 0, identifier2, seq2, payload2)
	ip2 := buildIPv4PacketWithTOSAndDF(srcIP, dstIP, 1, 0x04, false, echo2)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip2))

	reply2 := buildICMPSegment(0, 0, 0, identifier2, seq2, payload2)
	ipReply2 := buildIPv4PacketWithTOSAndDF(dstIP, srcIP, 1, 0x04, false, reply2)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, ipReply2))

	return frames
}

// buildECNProbe builds nmap's ECN-support probe: a SYN packet to an open
// port with CWR+ECE flags set, the reserved bit immediately preceding CWR
// also set, urgent field 0xF7F5 despite URG not being set, ack=0, window=3,
// and TCP options WScale(10), NOP, MSS(1460), SACKPermitted, NOP, NOP.
// Per https://nmap.org/book/osdetect-methods.html.
func buildECNProbe(srcIP, dstIP string, dstPort uint16, srcMAC, dstMAC [6]byte) (frames [][]byte) {
	srcPort := randomPort()
	opts := []TCPOption{WScale(10), NOP(), MSS(1460), SACKPermitted(), NOP(), NOP()}
	optBytes := encodeTCPOptions(opts)
	headerLen := 20 + len(optBytes)
	dataOffset := byte(headerLen / 4)

	seq := rand.Uint32()
	seg := make([]byte, headerLen)
	binary.BigEndian.PutUint16(seg[0:], srcPort)
	binary.BigEndian.PutUint16(seg[2:], dstPort)
	binary.BigEndian.PutUint32(seg[4:], seq)
	binary.BigEndian.PutUint32(seg[8:], 0)
	seg[12] = (dataOffset << 4) | 0x01
	seg[13] = 0xC2
	binary.BigEndian.PutUint16(seg[14:], 3)
	binary.BigEndian.PutUint16(seg[18:], 0xF7F5)
	copy(seg[20:], optBytes)

	ip := buildIPv4Packet(srcIP, dstIP, 6, seg)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))

	respSeq := rand.Uint32()
	respOpts := []TCPOption{MSS(1460), SACKPermitted(), WScale(7)}
	respSeg := buildTCPSegmentWithOptions(dstPort, srcPort, 0x12, respSeq, seq+1, 65535, respOpts, nil)
	respIP := buildIPv4Packet(dstIP, srcIP, 6, respSeg)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, respIP))

	ackSeg := buildTCPSegment(srcPort, dstPort, 0x10, seq+1, respSeq+1, nil)
	ackIP := buildIPv4Packet(srcIP, dstIP, 6, ackSeg)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ackIP))

	return frames
}

// buildT2T7Probes builds nmap's T2 through T7 TCP probes, per
// https://nmap.org/book/osdetect-methods.html. All six share the same
// options (WScale, NOP, MSS(265), Timestamp, SACKPermitted), except T7 uses
// WScale(15) instead of 10. Open-port probes (T2-T4) and closed-port probes
// (T5-T7) use openPort/closedPort respectively. Includes plausible
// responses; nmap's spec defines only what nmap sends, not target behavior.
func buildT2T7Probes(srcIP, dstIP string, openPort, closedPort uint16, srcMAC, dstMAC [6]byte) (frames [][]byte) {
	type t2t7Spec struct {
		flags   uint8
		df      bool
		window  uint16
		port    uint16
		wscale  byte
		noReply bool
	}
	specs := []t2t7Spec{
		{0x00, true, 128, openPort, 10, true},       // T2: NULL — many stacks send no response
		{0x2B, false, 256, openPort, 10, false},     // T3: SYN+FIN+URG+PSH
		{0x10, true, 1024, openPort, 10, false},     // T4: ACK
		{0x02, false, 31337, closedPort, 10, false}, // T5: SYN
		{0x10, true, 32768, closedPort, 10, false},  // T6: ACK
		{0x29, false, 65535, closedPort, 15, false}, // T7: FIN+PSH+URG
	}

	for _, spec := range specs {
		srcPort := randomPort()
		opts := []TCPOption{WScale(spec.wscale), NOP(), MSS(265), Timestamp(0xFFFFFFFF, 0), SACKPermitted()}
		seq := rand.Uint32()
		seg := buildTCPSegmentWithOptions(srcPort, spec.port, spec.flags, seq, 0, spec.window, opts, nil)
		ip := buildIPv4PacketWithTOSAndDF(srcIP, dstIP, 6, 0x00, spec.df, seg)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))

		if spec.noReply {
			continue
		}

		var respFlags uint8 = 0x14 // RST+ACK
		ackVal := seq
		if spec.flags&0x02 != 0 { // probe had SYN set, so the response acks seq+1
			ackVal = seq + 1
		}
		if spec.flags == 0x02 {
			respFlags = 0x12 // SYN+ACK for a bare SYN probe (T5)
		}
		respSeq := rand.Uint32()
		respSeg := buildTCPSegment(spec.port, srcPort, respFlags, respSeq, ackVal, nil)
		respIP := buildIPv4Packet(dstIP, srcIP, 6, respSeg)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, respIP))
	}
	return frames
}

// buildIPv4PacketWithID is buildIPv4Packet with an explicit IP ID value,
// needed for nmap's U1 UDP probe, which requires a fixed ID of 0x1042.
func buildIPv4PacketWithID(srcIP, dstIP string, protocol uint8, id uint16, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:], id)
	pkt[8] = 64
	pkt[9] = protocol
	binary.BigEndian.PutUint32(pkt[12:], ipToUint32(srcIP))
	binary.BigEndian.PutUint32(pkt[16:], ipToUint32(dstIP))
	copy(pkt[20:], payload)
	checksum := ipChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:], checksum)
	return pkt
}

// buildU1Probe builds nmap's U1 UDP probe: sent to a closed port, payload
// is 300 bytes of 'C' (0x43), IP ID fixed at 0x1042. Includes a plausible
// ICMP port-unreachable response, which is what a real closed UDP port
// (with no firewall) would send back.
func buildU1Probe(srcIP, dstIP string, srcPort, closedPort uint16, srcMAC, dstMAC [6]byte) (probe []byte, response []byte) {
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = 0x43 // 'C'
	}
	udp := buildUDPDatagram(srcPort, closedPort, payload)
	ip := buildIPv4PacketWithID(srcIP, dstIP, 17, 0x1042, udp)
	probe = buildEthernetFrame(srcMAC, dstMAC, ip)

	// ICMP type 3 (destination unreachable), code 3 (port unreachable).
	// Per RFC 792, the payload echoes back the original IP header plus at
	// least 8 bytes of the original datagram (here: the UDP header).
	originalHeader := ip[:20]
	originalUDPHeader := udp[:8]
	icmpPayload := append(append([]byte{}, originalHeader...), originalUDPHeader...)
	icmp := buildICMPSegment(3, 3, 0, 0, 0, icmpPayload)
	respIP := buildIPv4Packet(dstIP, srcIP, 1, icmp)
	response = buildEthernetFrame(dstMAC, srcMAC, respIP)

	return probe, response
}

// ─── DCERPC bind PDUs for WMI/DCOM lateral movement ──────────────────────────
//
// dcerpcUUID encodes a UUID into DCE/RPC wire format: Data1 (4 bytes) and
// Data2/Data3 (2 bytes each) are little-endian, but Data4 (the trailing 8
// bytes) is kept in the order given — this mixed-endian encoding is how
// every UUID appears in a DCERPC PDU (bind, bind_ack, interface/transfer
// syntax fields), per DCE 1.1 (C706) and confirmed against real captures
// of DCOM/WMI traffic (e.g. Wireshark's own UUID field display order).
// data1/data2/data3 are given in the conventional hex-string grouping
// (e.g. for F309AD18-D86A-11d0-A075-00C04FB68820: data1=0xF309AD18,
// data2=0xD86A, data3=0x11D0, data4={0xA0,0x75,0x00,0xC0,0x4F,0xB6,0x88,0x20}).
func dcerpcUUID(data1 uint32, data2, data3 uint16, data4 [8]byte) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], data1)
	binary.LittleEndian.PutUint16(buf[4:6], data2)
	binary.LittleEndian.PutUint16(buf[6:8], data3)
	copy(buf[8:16], data4[:])
	return buf
}

// Real, spec-verified DCERPC interface/transfer-syntax UUIDs used by WMI and
// DCOM lateral movement. Sources: [MS-WMI] §1.9 / [MS-DCOM] (Microsoft Learn,
// openspecs), cross-checked against Impacket's dcom/wmi.py and dcomrt.py and
// the go-msrpc library, which independently agree on all three values below.
var (
	// IWbemLevel1Login: the interface WMI clients bind to first (NTLMLogin),
	// per [MS-WMI] §1.9 Standards Assignments and the WMI initialization
	// sequence in [MS-WMI] §3.1.4.1.
	uuidIWbemLevel1Login = dcerpcUUID(0xF309AD18, 0xD86A, 0x11D0, [8]byte{0xA0, 0x75, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20})

	// IRemoteSCMActivator: the DCOM activation interface whose
	// RemoteCreateInstance (opnum 4) method instantiates a remote COM
	// object — the mechanism DCOM lateral movement (e.g. MMC20.Application)
	// relies on. Per [MS-DCOM] §3.1.2.5.2.2 / dcom package UUID tables.
	uuidIRemoteSCMActivator = dcerpcUUID(0x000001A0, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46})

	// NDR (Network Data Representation) transfer syntax, version 2.0 — the
	// standard DCE/RPC wire encoding negotiated in virtually every bind,
	// independent of which interface is being bound to.
	uuidNDRTransferSyntax = dcerpcUUID(0x8A885D04, 0x1CEB, 0x11C9, [8]byte{0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60})
)

// buildDCERPCBind builds a DCERPC bind PDU (PTYPE=11) requesting a single
// presentation context: the given interface UUID/version, with the
// standard NDR transfer syntax (version 2.0). callID is the RPC call
// identifier (arbitrary per-conversation counter, starts at 1 in practice).
func buildDCERPCBind(callID uint32, ifaceUUID []byte, ifaceVersionMajor, ifaceVersionMinor uint16) []byte {
	// Presentation context: p_cont_id(2) + n_transfer_syn(1) + reserved(1)
	// + abstract_syntax{uuid(16)+verMajor(2)+verMinor(2)} + one
	// transfer_syntax{uuid(16)+version(4)}
	contCtx := make([]byte, 2, 4+20+20)
	binary.LittleEndian.PutUint16(contCtx, 0) // p_cont_id = 0 (first/only context in this bind)
	contCtx = append(contCtx, 0x01, 0x00)     // n_transfer_syn=1, reserved=0
	contCtx = append(contCtx, ifaceUUID...)
	verBuf := make([]byte, 4)
	binary.LittleEndian.PutUint16(verBuf[0:2], ifaceVersionMajor)
	binary.LittleEndian.PutUint16(verBuf[2:4], ifaceVersionMinor)
	contCtx = append(contCtx, verBuf...)
	contCtx = append(contCtx, uuidNDRTransferSyntax...)
	tsVerBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(tsVerBuf, 2) // NDR transfer syntax version 2.0 (major=2, minor=0, packed as one uint32)
	contCtx = append(contCtx, tsVerBuf...)

	body := make([]byte, 0, 12+len(contCtx))
	maxFrag := make([]byte, 2)
	binary.LittleEndian.PutUint16(maxFrag, 4280) // max_xmit_frag — common real-world default
	body = append(body, maxFrag...)
	body = append(body, maxFrag...)             // max_recv_frag, same value
	body = append(body, 0x00, 0x00, 0x00, 0x00) // assoc_group_id = 0 (new association)
	body = append(body, 0x01)                   // n_context_elem = 1
	body = append(body, 0x00, 0x00, 0x00)       // reserved + 2-byte pad
	body = append(body, contCtx...)

	return wrapDCERPCCommonHeader(11, callID, body) // PTYPE 11 = bind
}

// buildDCERPCBindAck builds the corresponding bind_ack (PTYPE=12), accepting
// the single presentation context offered, echoing the same NDR transfer
// syntax back (acceptance, per DCE 1.1 §12.6.3.3).
func buildDCERPCBindAck(callID uint32) []byte {
	secAddr := []byte("\\PIPE\\wbem\x00") // typical secondary address for WMI/DCOM-over-SMB-named-pipe transport; padded below
	secAddrLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(secAddrLen, uint16(len(secAddr)))

	body := make([]byte, 0, 64)
	maxFrag := make([]byte, 2)
	binary.LittleEndian.PutUint16(maxFrag, 4280)
	body = append(body, maxFrag...)
	body = append(body, maxFrag...)
	body = append(body, 0x00, 0x00, 0x00, 0x00) // assoc_group_id
	body = append(body, secAddrLen...)
	body = append(body, secAddr...)
	for len(body)%4 != 0 {
		body = append(body, 0x00) // pad secondary address to 4-byte boundary
	}
	body = append(body, 0x01)             // n_results = 1
	body = append(body, 0x00, 0x00, 0x00) // reserved + pad
	body = append(body, 0x00, 0x00)       // result = 0 (acceptance)
	body = append(body, 0x00, 0x00)       // reason = 0
	body = append(body, uuidNDRTransferSyntax...)
	tsVerBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(tsVerBuf, 2)
	body = append(body, tsVerBuf...)

	return wrapDCERPCCommonHeader(12, callID, body) // PTYPE 12 = bind_ack
}

// wrapDCERPCCommonHeader prepends the 16-byte DCERPC common header (rpc_vers,
// rpc_vers_minor, PTYPE, pfc_flags, packed_drep, frag_length, auth_length,
// call_id) per DCE 1.1 §12.6.3, to the given PDU-type-specific body.
func wrapDCERPCCommonHeader(ptype byte, callID uint32, body []byte) []byte {
	totalLen := 16 + len(body)
	hdr := make([]byte, 16)
	hdr[0] = 5 // rpc_vers
	hdr[1] = 0 // rpc_vers_minor
	hdr[2] = ptype
	hdr[3] = 0x03 // pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG (single-fragment PDU)
	hdr[4] = 0x10 // packed_drep: little-endian integer + IEEE float (standard on-wire default)
	hdr[5] = 0x00
	hdr[6] = 0x00
	hdr[7] = 0x00
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(totalLen))
	binary.LittleEndian.PutUint16(hdr[10:12], 0) // auth_length = 0, no auth verifier
	binary.LittleEndian.PutUint32(hdr[12:16], callID)
	return append(hdr, body...)
}

// buildDCERPCRequestStub builds a minimal DCERPC request PDU (PTYPE=0)
// carrying an approximated call body. Unlike the bind/bind_ack frames
// above, the actual NDR-marshaled argument structure for a real
// WMI NTLMLogin or DCOM RemoteCreateInstance call (ORPCTHIS, marshaled
// CLSID/IID arrays, etc.) is not reproduced here — that structure is
// considerably deeper than the bind layer and isn't verified byte-accurate,
// so this carries a labeled text approximation as the stub data instead of
// fabricated NDR bytes. The header (PTYPE, call_id, opnum) is real.
func buildDCERPCRequestStub(callID uint32, opnum uint16, approxPayload []byte) []byte {
	body := make([]byte, 0, 8+len(approxPayload))
	body = append(body, 0x00, 0x00, 0x00, 0x00) // alloc_hint = 0 (unspecified)
	body = append(body, 0x00, 0x00)             // p_cont_id = 0 (matches bind's context)
	opnumBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(opnumBuf, opnum)
	body = append(body, opnumBuf...)
	body = append(body, approxPayload...)
	return wrapDCERPCCommonHeader(0, callID, body) // PTYPE 0 = request
}

// buildDCERPCResponseStub mirrors buildDCERPCRequestStub for the response
// side (PTYPE=2), same approximation caveat applies to the payload.
func buildDCERPCResponseStub(callID uint32, approxPayload []byte) []byte {
	body := make([]byte, 0, 8+len(approxPayload))
	body = append(body, 0x00, 0x00, 0x00, 0x00) // alloc_hint
	body = append(body, 0x00, 0x00)             // p_cont_id
	body = append(body, 0x00, 0x00)             // cancel_count + reserved
	body = append(body, approxPayload...)
	return wrapDCERPCCommonHeader(2, callID, body) // PTYPE 2 = response
}

// ── SMB2 (RFC 1002) ──────────────────────────────────────────────────────────

// buildSMB2Header builds a 64-byte SMB2 common header (Signature, StructureSize,
// CreditCharge, Status, Command, CreditRequestResponse, Flags, NextCommand,
// MessageID, AsyncID/TreeID, SessionID, Signature).
func buildSMB2Header(command uint16, messageID uint64, treeID uint32, sessionID uint64, payload []byte) []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFF, 0x53, 0x4D, 0x42})  // Signature: "\xFFSMB"
	binary.LittleEndian.PutUint16(hdr[4:6], 0x0040) // StructureSize = 64
	binary.LittleEndian.PutUint16(hdr[6:8], 0)      // CreditCharge
	binary.LittleEndian.PutUint32(hdr[8:12], 0)     // Status = 0 (success)
	binary.LittleEndian.PutUint16(hdr[12:14], command)
	binary.LittleEndian.PutUint16(hdr[14:16], 1) // CreditRequestResponse
	binary.LittleEndian.PutUint32(hdr[16:20], 0) // Flags
	binary.LittleEndian.PutUint32(hdr[20:24], 0) // NextCommand = 0 (single PDU)
	binary.LittleEndian.PutUint64(hdr[24:32], messageID)
	binary.LittleEndian.PutUint32(hdr[32:36], 0) // Reserved (ProcessID in requests)
	binary.LittleEndian.PutUint32(hdr[36:40], treeID)
	binary.LittleEndian.PutUint64(hdr[40:48], sessionID)
	// Signature (48:64) = 16 bytes of zeros (HMAC, not computed for prototype)
	return hdr
}

// buildSMB2WriteRequest builds a SMB2 WRITE request command (command 15): 49-byte
// fixed structure + variable-length data buffer. The DataOffset field (at byte
// offset 66-67 from the start of the SMB2 header) is automatically computed to
// point to the payload buffer.
func buildSMB2WriteRequest(payload []byte) []byte {
	cmd := make([]byte, 49)
	binary.LittleEndian.PutUint16(cmd[0:2], 0x0031)               // StructureSize = 49
	binary.LittleEndian.PutUint16(cmd[2:4], 64+49)                // DataOffset (from start of SMB2 header)
	binary.LittleEndian.PutUint32(cmd[4:8], uint32(len(payload))) // Length
	binary.LittleEndian.PutUint64(cmd[8:16], 0)                   // Offset (file offset)
	// FileID (16:32) = 16 bytes of zeros
	binary.LittleEndian.PutUint32(cmd[32:36], 0) // Channel
	binary.LittleEndian.PutUint32(cmd[36:40], 0) // RemainingLength
	binary.LittleEndian.PutUint16(cmd[40:42], 0) // WriteChannelInfoOffset
	binary.LittleEndian.PutUint16(cmd[42:44], 0) // WriteChannelInfoLength
	binary.LittleEndian.PutUint32(cmd[44:48], 0) // Flags
	return append(cmd, payload...)
}

// PCAPSMBChannel generates a PCAP frame for SMB named-pipe C2: TCP handshake
// on port 445 (SMB), followed by a real SMB2 WRITE request to a named pipe
// carrying C2 payload. The SMB2 structures (header + WriteRequest) are
// RFC-compliant enough for Wireshark's dissector.
func PCAPSMBChannel(runID, attackerIP, targetIP, pipeName string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPSMBChannel attacker=%s target=%s pipe=%s", attackerIP, targetIP, pipeName)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()
	var frames [][]byte

	// TCP SYN
	syn := buildTCPSegment(srcPort, 445, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	clientSeq++

	// TCP SYN-ACK
	synAck := buildTCPSegment(445, srcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	serverSeq++

	// TCP ACK
	ack := buildTCPSegment(srcPort, 445, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

	// SMB2 WriteRequest on the named pipe
	payload := []byte(fmt.Sprintf("Covert channel payload on %s: encrypted C2 command", pipeName))
	writeReq := buildSMB2WriteRequest(payload)
	header := buildSMB2Header(15, 1, 0, 1, writeReq)
	smbData := append(header, writeReq...)

	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 445, 0x18, clientSeq, serverSeq, smbData))))
	clientSeq += uint32(len(smbData))

	finalAck := buildTCPSegment(445, srcPort, 0x10, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, finalAck)))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "smb_channel", finalFrames, defaultDuration)
	logInfo("Return from PCAPSMBChannel frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPLateralWMI generates PCAP frames for WMI lateral movement: a real
// DCERPC bind/bind_ack to IWbemLevel1Login on port 135 (the genuine
// activation/login interface real WMI tooling binds to first), followed
// by an approximated Win32_Process.Create call on the dynamic high port
// the activation negotiates — matching the two-leg shape runWMILateral's
// syslog/flow telemetry already represents (one flow to 135, one to a
// dynamic highPort).
func PCAPLateralWMI(runID, attackerIP, targetIP string, highPort uint16) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPLateralWMI attacker=%s target=%s highPort=%d", attackerIP, targetIP, highPort)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	var frames [][]byte

	// Leg 1: port 135, DCERPC bind/bind_ack to IWbemLevel1Login
	srcPort1 := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()

	syn := buildTCPSegment(srcPort1, 135, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	clientSeq++
	synAck := buildTCPSegment(135, srcPort1, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	serverSeq++
	ack := buildTCPSegment(srcPort1, 135, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

	bind := buildDCERPCBind(1, uuidIWbemLevel1Login, 0, 0)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort1, 135, 0x18, clientSeq, serverSeq, bind))))
	clientSeq += uint32(len(bind))
	bindAck := buildDCERPCBindAck(1)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(135, srcPort1, 0x18, serverSeq, clientSeq, bindAck))))
	serverSeq += uint32(len(bindAck))
	finalAck := buildTCPSegment(srcPort1, 135, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, finalAck)))

	// Leg 2: dynamic high port, approximated Win32_Process.Create exploitation
	srcPort2 := randomPort()
	clientSeq2, serverSeq2 := rand.Uint32(), rand.Uint32()

	syn2 := buildTCPSegment(srcPort2, highPort, 0x02, clientSeq2, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn2)))
	clientSeq2++
	synAck2 := buildTCPSegment(highPort, srcPort2, 0x12, serverSeq2, clientSeq2, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck2)))
	serverSeq2++
	ack2 := buildTCPSegment(srcPort2, highPort, 0x10, clientSeq2, serverSeq2, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack2)))

	createReq := buildDCERPCRequestStub(1, 24, []byte("Win32_Process.Create(CommandLine='cmd.exe /c whoami')"))
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort2, highPort, 0x18, clientSeq2, serverSeq2, createReq))))
	clientSeq2 += uint32(len(createReq))
	createResp := buildDCERPCResponseStub(1, []byte("ReturnValue=0 ProcessId=4821"))
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(highPort, srcPort2, 0x18, serverSeq2, clientSeq2, createResp))))
	serverSeq2 += uint32(len(createResp))
	finalAck2 := buildTCPSegment(srcPort2, highPort, 0x10, clientSeq2, serverSeq2, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, finalAck2)))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "lateral_wmi", finalFrames, defaultDuration)
	logInfo("Return from PCAPLateralWMI frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPLateralDCOM generates PCAP frames for DCOM lateral movement (e.g.
// MMC20.Application abuse): a single TCP conversation on port 135 with a
// real DCERPC bind/bind_ack to IRemoteSCMActivator, followed by an
// approximated RemoteCreateInstance (opnum 4) call/response — matching
// runDCOMLateral's existing single-flow (port 135 only) telemetry shape.
func PCAPLateralDCOM(runID, attackerIP, targetIP string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPLateralDCOM attacker=%s target=%s", attackerIP, targetIP)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()
	var frames [][]byte

	syn := buildTCPSegment(srcPort, 135, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	clientSeq++
	synAck := buildTCPSegment(135, srcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	serverSeq++
	ack := buildTCPSegment(srcPort, 135, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

	bind := buildDCERPCBind(1, uuidIRemoteSCMActivator, 0, 0)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 135, 0x18, clientSeq, serverSeq, bind))))
	clientSeq += uint32(len(bind))
	bindAck := buildDCERPCBindAck(1)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(135, srcPort, 0x18, serverSeq, clientSeq, bindAck))))
	serverSeq += uint32(len(bindAck))
	midAck := buildTCPSegment(srcPort, 135, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, midAck)))

	createReq := buildDCERPCRequestStub(1, 4, []byte("RemoteCreateInstance(CLSID=MMC20.Application)"))
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 135, 0x18, clientSeq, serverSeq, createReq))))
	clientSeq += uint32(len(createReq))
	createResp := buildDCERPCResponseStub(1, []byte("ErrorCode=0"))
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(135, srcPort, 0x18, serverSeq, clientSeq, createResp))))
	serverSeq += uint32(len(createResp))
	finalAck := buildTCPSegment(srcPort, 135, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, finalAck)))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "lateral_dcom", finalFrames, defaultDuration)
	logInfo("Return from PCAPLateralDCOM frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPLateralRDPHijack generates PCAP frames for RDP session hijacking
// (tscon.exe-style): a TCP handshake on port 3389 followed by the same
// rdpClientPDU connection-request payload PCAPBruteForce's "rdp" case
// uses (so this stays byte-consistent with the rest of the codebase's RDP
// representation), then an approximated session-takeover exchange.
func PCAPLateralRDPHijack(runID, attackerIP, targetIP string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPLateralRDPHijack attacker=%s target=%s", attackerIP, targetIP)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()
	var frames [][]byte

	syn := buildTCPSegment(srcPort, 3389, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	clientSeq++
	synAck := buildTCPSegment(3389, srcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	serverSeq++
	ack := buildTCPSegment(srcPort, 3389, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

	connReq := rdpClientPDU[:]
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 3389, 0x18, clientSeq, serverSeq, connReq))))
	clientSeq += uint32(len(connReq))
	connConfirm := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00} // minimal X.224 connection confirm
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(3389, srcPort, 0x18, serverSeq, clientSeq, connConfirm))))
	serverSeq += uint32(len(connConfirm))
	midAck := buildTCPSegment(srcPort, 3389, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, midAck)))

	// Approximated session takeover (tscon.exe redirects an existing session
	// without re-authenticating) — not a byte-accurate RDP PDU, same caveat
	// as the DCERPC request/response stubs above.
	hijackPayload := []byte("tscon 2 /dest:console")
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 3389, 0x18, clientSeq, serverSeq, hijackPayload))))
	clientSeq += uint32(len(hijackPayload))
	hijackAck := buildTCPSegment(3389, srcPort, 0x10, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, hijackAck)))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "lateral_rdp_hijack", finalFrames, defaultDuration)
	logInfo("Return from PCAPLateralRDPHijack frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// ── DHCP / BOOTP (RFC 2131) ───────────────────────────────────────────────────

// buildDHCPOption builds a single DHCP option as a [code, length, ...data] TLV.
func buildDHCPOption(code byte, data []byte) []byte {
	opt := make([]byte, 2+len(data))
	opt[0] = code
	opt[1] = byte(len(data))
	copy(opt[2:], data)
	return opt
}

// buildDHCPPacket builds a full BOOTP/DHCP packet: 236-byte fixed header,
// 4-byte magic cookie (0x63825363), then options, then the 0xff End option.
// op: 1=BOOTREQUEST (client->server), 2=BOOTREPLY (server->client).
func buildDHCPPacket(op byte, xid uint32, clientMAC [6]byte, ciaddr, yiaddr, siaddr, giaddr string, optionsBytes []byte) []byte {
	pkt := make([]byte, 236)
	pkt[0] = op
	pkt[1] = 0x01 // htype: Ethernet
	pkt[2] = 0x06 // hlen: 6
	pkt[3] = 0x00 // hops
	binary.BigEndian.PutUint32(pkt[4:], xid)
	binary.BigEndian.PutUint16(pkt[8:], 0)  // secs
	binary.BigEndian.PutUint16(pkt[10:], 0) // flags
	copy(pkt[12:16], dhcpIPv4Bytes(ciaddr))
	copy(pkt[16:20], dhcpIPv4Bytes(yiaddr))
	copy(pkt[20:24], dhcpIPv4Bytes(siaddr))
	copy(pkt[24:28], dhcpIPv4Bytes(giaddr))
	copy(pkt[28:34], clientMAC[:]) // chaddr (16 bytes, first 6 used for Ethernet)
	// sname (offset 44, 64 bytes) and file (offset 108, 128 bytes) left zero
	magicCookie := []byte{0x63, 0x82, 0x53, 0x63}
	full := append(append([]byte{}, pkt...), magicCookie...)
	full = append(full, optionsBytes...)
	full = append(full, 0xff) // End option
	return full
}

// dhcpIPv4Bytes parses a dotted-quad string into 4 raw bytes; returns
// 0.0.0.0 on parse failure rather than panicking, since DHCP fields are
// often legitimately "0.0.0.0" (e.g. ciaddr before a lease is assigned).
// Named distinctly from any existing ipToUint32-style helper since DHCP
// needs raw bytes, not a packed uint32.
func dhcpIPv4Bytes(ip string) []byte {
	var a, b, c, d int
	n, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	if err != nil || n != 4 {
		return []byte{0, 0, 0, 0}
	}
	return []byte{byte(a), byte(b), byte(c), byte(d)}
}

// ── PCAP generators ───────────────────────────────────────────────────────────

// PCAPDHCPStarvation simulates a DHCP starvation attack: many DISCOVER/REQUEST
// pairs each from a different spoofed MAC, with OFFER/ACK responses from the
// server until the pool is exhausted. The last 3 requests get DHCPNAK
// (no available IPs) instead of an offer.
func PCAPDHCPStarvation(runID string, count int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPDHCPStarvation count=%d", count)

	if count > 200 {
		count = 200
	}

	// Find DHCP server — use switch IP as fallback
	var serverIP string
	var serverMAC [6]byte
	for _, d := range getAllDevices() {
		if d.DeviceType == "switch" || d.DeviceType == "router" {
			serverIP = d.IPAddress
			serverMAC = parseMACAddress(d.MACAddress)
			break
		}
	}
	if serverIP == "" {
		serverIP = "10.0.1.1"
		serverMAC = [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x01}
	}

	broadcastMAC := parseMACAddress("FF:FF:FF:FF:FF:FF")
	exhaustedAt := count - 3 // last 3 requests get DHCPNAK

	var frames [][]byte
	for i := 0; i < count; i++ {
		clientMAC := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i % 256)}
		xid := uint32(0x10000 + i)

		// DHCP Discover — spoofed MAC broadcasts to find server
		discOpts := buildDHCPOption(53, []byte{0x01}) // Discover
		discOpts = append(discOpts, buildDHCPOption(61, append([]byte{0x01}, clientMAC[:]...))...)
		discOpts = append(discOpts, buildDHCPOption(55, []byte{0x01, 0x03, 0x06, 0x0f})...)
		discover := buildDHCPPacket(0x01, xid, clientMAC, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", discOpts)
		discFrame := buildEthernetFrame(clientMAC, broadcastMAC, buildIPv4Packet("0.0.0.0", "255.255.255.255", 17, buildUDPDatagram(68, 67, discover)))
		frames = append(frames, discFrame)

		if i < exhaustedAt {
			// Pool not yet exhausted — server sends DHCP Offer
			offeredIP := fmt.Sprintf("10.0.1.%d", (i%200)+10)
			offerOpts := buildDHCPOption(53, []byte{0x02})                                        // Offer
			offerOpts = append(offerOpts, buildDHCPOption(51, []byte{0x00, 0x01, 0x51, 0x80})...) // Lease 86400s
			offerOpts = append(offerOpts, buildDHCPOption(54, dhcpIPv4Bytes(serverIP))...)        // Server ID
			offerOpts = append(offerOpts, buildDHCPOption(1, []byte{255, 255, 255, 0})...)        // Subnet mask
			offerOpts = append(offerOpts, buildDHCPOption(3, dhcpIPv4Bytes(serverIP))...)         // Router
			offer := buildDHCPPacket(0x02, xid, clientMAC, "0.0.0.0", offeredIP, serverIP, "0.0.0.0", offerOpts)
			offerFrame := buildEthernetFrame(serverMAC, clientMAC, buildIPv4Packet(serverIP, "255.255.255.255", 17, buildUDPDatagram(67, 68, offer)))
			frames = append(frames, offerFrame)

			// DHCP Request — client requests the offered IP
			reqOpts := buildDHCPOption(53, []byte{0x03})                                // Request
			reqOpts = append(reqOpts, buildDHCPOption(50, dhcpIPv4Bytes(offeredIP))...) // Requested IP
			reqOpts = append(reqOpts, buildDHCPOption(54, dhcpIPv4Bytes(serverIP))...)  // Server ID
			request := buildDHCPPacket(0x01, xid, clientMAC, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", reqOpts)
			reqFrame := buildEthernetFrame(clientMAC, broadcastMAC, buildIPv4Packet("0.0.0.0", "255.255.255.255", 17, buildUDPDatagram(68, 67, request)))
			frames = append(frames, reqFrame)

			// DHCP ACK — server confirms lease
			ackOpts := buildDHCPOption(53, []byte{0x05}) // ACK
			ackOpts = append(ackOpts, buildDHCPOption(51, []byte{0x00, 0x01, 0x51, 0x80})...)
			ackOpts = append(ackOpts, buildDHCPOption(54, dhcpIPv4Bytes(serverIP))...)
			ackOpts = append(ackOpts, buildDHCPOption(1, []byte{255, 255, 255, 0})...)
			dhcpAck := buildDHCPPacket(0x02, xid, clientMAC, "0.0.0.0", offeredIP, serverIP, "0.0.0.0", ackOpts)
			ackFrame := buildEthernetFrame(serverMAC, clientMAC, buildIPv4Packet(serverIP, "255.255.255.255", 17, buildUDPDatagram(67, 68, dhcpAck)))
			frames = append(frames, ackFrame)
		} else {
			// Pool exhausted — server sends DHCPNAK (no available IPs)
			nakOpts := buildDHCPOption(53, []byte{0x06}) // NAK
			nakOpts = append(nakOpts, buildDHCPOption(54, dhcpIPv4Bytes(serverIP))...)
			nakOpts = append(nakOpts, buildDHCPOption(56, []byte("No available IPs in pool"))...) // Message
			nak := buildDHCPPacket(0x02, xid, clientMAC, "0.0.0.0", "0.0.0.0", serverIP, "0.0.0.0", nakOpts)
			nakFrame := buildEthernetFrame(serverMAC, broadcastMAC, buildIPv4Packet(serverIP, "255.255.255.255", 17, buildUDPDatagram(67, 68, nak)))
			frames = append(frames, nakFrame)
		}
	}

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "dhcp_starvation", finalFrames, defaultDuration)
	logInfo("Return from PCAPDHCPStarvation frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPRogueDHCP simulates a rogue DHCP server racing the legitimate server:
// 1. Victim broadcasts DHCP Discover
// 2. Attacker's rogue OFFER arrives first (attacker as router and DHCP server)
// 3. Legitimate server's OFFER arrives second (too late)
// 4. Victim accepts attacker's offer with DHCP Request
// 5. Attacker sends DHCP ACK — victim now uses attacker as gateway
// 6. Legitimate server sends NAK — its offer was not accepted
func PCAPRogueDHCP(runID, attackerIP, fakeGateway string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPRogueDHCP attacker=%s fakeGateway=%s", attackerIP, fakeGateway)

	attackerMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	broadcastMAC := parseMACAddress("FF:FF:FF:FF:FF:FF")
	victimMAC := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99}
	xid := uint32(0x99887766)

	// Find legitimate DHCP server
	var legitServerIP string
	var legitServerMAC [6]byte
	for _, d := range getAllDevices() {
		if d.DeviceType == "switch" || d.DeviceType == "router" {
			legitServerIP = d.IPAddress
			legitServerMAC = parseMACAddress(d.MACAddress)
			break
		}
	}
	if legitServerIP == "" {
		legitServerIP = "10.0.0.1"
		legitServerMAC = [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x01}
	}

	var frames [][]byte

	// Frame 1: Victim broadcasts DHCP Discover
	discOpts := buildDHCPOption(53, []byte{0x01}) // Discover
	discOpts = append(discOpts, buildDHCPOption(61, append([]byte{0x01}, victimMAC[:]...))...)
	discOpts = append(discOpts, buildDHCPOption(55, []byte{0x01, 0x03, 0x06, 0x0f})...)
	disc := buildDHCPPacket(0x01, xid, victimMAC, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", discOpts)
	discFrame := buildEthernetFrame(victimMAC, broadcastMAC, buildIPv4Packet("0.0.0.0", "255.255.255.255", 17, buildUDPDatagram(68, 67, disc)))
	frames = append(frames, discFrame)

	// Frame 2: Attacker's rogue OFFER arrives first — attacker as router and DHCP server
	rogueOfferOpts := buildDHCPOption(53, []byte{0x02})                                             // Offer
	rogueOfferOpts = append(rogueOfferOpts, buildDHCPOption(54, dhcpIPv4Bytes(attackerIP))...)      // Server ID = attacker
	rogueOfferOpts = append(rogueOfferOpts, buildDHCPOption(51, []byte{0x00, 0x01, 0x51, 0x80})...) // Lease 86400s
	rogueOfferOpts = append(rogueOfferOpts, buildDHCPOption(1, dhcpIPv4Bytes("255.255.255.0"))...)  // Subnet mask
	rogueOfferOpts = append(rogueOfferOpts, buildDHCPOption(3, dhcpIPv4Bytes(attackerIP))...)       // Router = attacker
	rogueOfferOpts = append(rogueOfferOpts, buildDHCPOption(6, dhcpIPv4Bytes(attackerIP))...)       // DNS = attacker
	rogueOffer := buildDHCPPacket(0x02, xid, victimMAC, "0.0.0.0", "10.0.1.50", attackerIP, "0.0.0.0", rogueOfferOpts)
	rogueOfferFrame := buildEthernetFrame(attackerMAC, victimMAC, buildIPv4Packet(attackerIP, "255.255.255.255", 17, buildUDPDatagram(67, 68, rogueOffer)))
	frames = append(frames, rogueOfferFrame)

	// Frame 3: Legitimate server's OFFER arrives second (too late)
	legitOfferOpts := buildDHCPOption(53, []byte{0x02})                                           // Offer
	legitOfferOpts = append(legitOfferOpts, buildDHCPOption(54, dhcpIPv4Bytes(legitServerIP))...) // Server ID = legit
	legitOfferOpts = append(legitOfferOpts, buildDHCPOption(51, []byte{0x00, 0x01, 0x51, 0x80})...)
	legitOfferOpts = append(legitOfferOpts, buildDHCPOption(1, dhcpIPv4Bytes("255.255.255.0"))...)
	legitOfferOpts = append(legitOfferOpts, buildDHCPOption(3, dhcpIPv4Bytes(legitServerIP))...) // Router = legit
	legitOfferOpts = append(legitOfferOpts, buildDHCPOption(6, dhcpIPv4Bytes(legitServerIP))...) // DNS = legit
	legitOffer := buildDHCPPacket(0x02, xid, victimMAC, "0.0.0.0", "10.0.1.51", legitServerIP, "0.0.0.0", legitOfferOpts)
	legitOfferFrame := buildEthernetFrame(legitServerMAC, victimMAC, buildIPv4Packet(legitServerIP, "255.255.255.255", 17, buildUDPDatagram(67, 68, legitOffer)))
	frames = append(frames, legitOfferFrame)

	// Frame 4: Victim sends DHCP Request accepting attacker's offer
	reqOpts := buildDHCPOption(53, []byte{0x03})                                  // Request
	reqOpts = append(reqOpts, buildDHCPOption(54, dhcpIPv4Bytes(attackerIP))...)  // Server ID = attacker (accepted)
	reqOpts = append(reqOpts, buildDHCPOption(50, dhcpIPv4Bytes("10.0.1.50"))...) // Requested IP from attacker
	reqOpts = append(reqOpts, buildDHCPOption(61, append([]byte{0x01}, victimMAC[:]...))...)
	request := buildDHCPPacket(0x01, xid, victimMAC, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", reqOpts)
	requestFrame := buildEthernetFrame(victimMAC, broadcastMAC, buildIPv4Packet("0.0.0.0", "255.255.255.255", 17, buildUDPDatagram(68, 67, request)))
	frames = append(frames, requestFrame)

	// Frame 5: Attacker sends DHCP ACK — victim now uses attacker as gateway
	ackOpts := buildDHCPOption(53, []byte{0x05}) // ACK
	ackOpts = append(ackOpts, buildDHCPOption(54, dhcpIPv4Bytes(attackerIP))...)
	ackOpts = append(ackOpts, buildDHCPOption(51, []byte{0x00, 0x01, 0x51, 0x80})...)
	ackOpts = append(ackOpts, buildDHCPOption(1, dhcpIPv4Bytes("255.255.255.0"))...)
	ackOpts = append(ackOpts, buildDHCPOption(3, dhcpIPv4Bytes(attackerIP))...) // Router = attacker
	ackOpts = append(ackOpts, buildDHCPOption(6, dhcpIPv4Bytes(attackerIP))...) // DNS = attacker
	dhcpAck := buildDHCPPacket(0x02, xid, victimMAC, "0.0.0.0", "10.0.1.50", attackerIP, "0.0.0.0", ackOpts)
	dhcpAckFrame := buildEthernetFrame(attackerMAC, victimMAC, buildIPv4Packet(attackerIP, "255.255.255.255", 17, buildUDPDatagram(67, 68, dhcpAck)))
	frames = append(frames, dhcpAckFrame)

	// Frame 6: Legitimate server sends NAK — its offer was not accepted
	nakOpts := buildDHCPOption(53, []byte{0x06}) // NAK
	nakOpts = append(nakOpts, buildDHCPOption(54, dhcpIPv4Bytes(legitServerIP))...)
	nakOpts = append(nakOpts, buildDHCPOption(56, []byte("Request accepted by another server"))...)
	nak := buildDHCPPacket(0x02, xid, victimMAC, "0.0.0.0", "0.0.0.0", legitServerIP, "0.0.0.0", nakOpts)
	nakFrame := buildEthernetFrame(legitServerMAC, broadcastMAC, buildIPv4Packet(legitServerIP, "255.255.255.255", 17, buildUDPDatagram(67, 68, nak)))
	frames = append(frames, nakFrame)

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "rogue_dhcp", finalFrames, defaultDuration)
	logInfo("Return from PCAPRogueDHCP frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPDNSExfilMulti simulates DNS exfiltration as a sequence of TXT queries
// to base32-looking subdomains of the exfil domain, each query carrying one
// chunk of the encoded data. Named distinctly from PCAPDNSTunnel (which
// already exists and sends a fixed-count loop of single random-hex
// subdomains) since this needs the chunk count and domain driven by the
// calling attack's actual parameters, and a believable base32-style alphabet
// rather than full random hex per query.
func PCAPDNSExfilMulti(runID, attackerIP, dnsTargetIP, domain string, chunkCount int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPDNSExfilMulti attacker=%s dnsTarget=%s domain=%s chunks=%d", attackerIP, dnsTargetIP, domain, chunkCount)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}

	const chunkAlphabet = "abcdefghijklmnopqrstuvwxyz234567" // base32-ish charset for believable-looking encoded subdomains
	if chunkCount > 200 {
		chunkCount = 200 // cap PCAP size; syslog/netflow already reflect the full chunk count
	}
	var frames [][]byte
	for i := 0; i < chunkCount; i++ {
		chunk := make([]byte, 28)
		for j := range chunk {
			chunk[j] = chunkAlphabet[(i*7+j*13)%len(chunkAlphabet)] // deterministic pseudo-random-looking chunk per query
		}
		qname := string(chunk) + "." + domain
		query := buildDNSQueryType(qname, 0x0010) // TXT
		ip := buildIPv4Packet(attackerIP, dnsTargetIP, 17, buildUDPDatagram(uint16(50000+i%10000), 53, query))
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))
	}
	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "dns_exfil", finalFrames, defaultDuration)
	logInfo("Return from PCAPDNSExfilMulti frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPICMPTunnel simulates an ICMP tunnel: a sequence of ICMP echo requests
// with anomalously large (1400-byte) payloads to the C2 IP, each answered by
// an echo reply — a believable bidirectional covert channel shape. Checksum
// is left at 0 in the ICMP header, matching this file's existing convention
// for buildICMPSegment callers (writeICMPTunnelPCAP, PCAPICMPFlood) — recent
// Wireshark releases don't validate ICMP/UDP/TCP checksums by default, so
// this matches established precedent rather than introducing inconsistency.
func PCAPICMPTunnel(runID, attackerIP, c2IP string, count int) (string, error) {
	return buildICMPExchangePCAP(runID, "icmp_tunnel", attackerIP, c2IP, count, true)
}

// PCAPICMPExfil simulates one-way ICMP exfiltration: oversized echo requests
// carrying encoded data outbound, with no replies (data is leaving, not a
// two-way channel) — matching the one-way framing in runICMPExfil's syslog.
func PCAPICMPExfil(runID, attackerIP, c2IP string, packetCount int) (string, error) {
	return buildICMPExchangePCAP(runID, "icmp_exfil", attackerIP, c2IP, packetCount, false)
}

// buildICMPExchangePCAP is the shared builder behind PCAPICMPTunnel and
// PCAPICMPExfil: both are "attacker sends oversized ICMP echo requests to an
// external IP" attacks, differing only in whether replies are included
// (tunnel = bidirectional C2, exfil = one-way data push).
func buildICMPExchangePCAP(runID, attackName, attackerIP, c2IP string, count int, withReplies bool) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering %s attacker=%s c2=%s count=%d", attackName, attackerIP, c2IP, count)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}

	if count > 100 {
		count = 100 // cap PCAP size; syslog/netflow already reflect the full count
	}
	identifier := uint16(rand.Intn(65535))
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte('A' + i%26) // arbitrary tunnel/exfil filler payload
	}
	var frames [][]byte
	for i := 0; i < count; i++ {
		seq := uint16(i + 1)
		echoReq := buildICMPSegment(8, 0, 0, identifier, seq, payload) // type 8 = Echo Request, checksum=0 per file convention
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, c2IP, 1, echoReq)))

		if withReplies {
			echoReply := buildICMPSegment(0, 0, 0, identifier, seq, payload) // type 0 = Echo Reply
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(c2IP, attackerIP, 1, echoReply)))
		}
	}
	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, attackName, finalFrames, defaultDuration)
	logInfo("Return from %s frames=%d path=%s", attackName, len(finalFrames), path)
	return path, err
}

// ── Kerberos (RFC 4120) — simplified but ASN.1-structurally-correct ─────────
//
// These builders implement the real outer ASN.1 shape (application tags,
// KDC-REQ/KDC-REQ-BODY/KDC-REP SEQUENCEs, PrincipalName, Realm,
// KerberosTime, EncryptedData) using berTLV so every length is computed
// from actual content rather than hardcoded — the class of bug that broke
// the SNMP encoders earlier. What's intentionally NOT byte-accurate: optional
// fields (padata, rtime, addresses, kdc-options flag semantics beyond an
// all-zero placeholder), and all "encrypted" ciphertext fields are random
// filler bytes of plausible length, not real Kerberos encryption output —
// labeled below at each call site. Good enough for Wireshark to recognize
// and dissect as Kerberos with correct field values for cname/realm/sname/
// till/nonce/etype, not a faithful reproduction of real encrypted traffic.

func kerberosString(s string) []byte {
	return berTLV(0x1b, []byte(s))
}

func kerberosPrincipalName(nameType int, nameStrings []string) []byte {
	nt := berTLV(0xa0, berInt(nameType))
	var strs []byte
	for _, s := range nameStrings {
		strs = append(strs, kerberosString(s)...)
	}
	ns := berTLV(0xa1, berTLV(0x30, strs))
	return berTLV(0x30, append(nt, ns...))
}

func kerberosRealm(name string) []byte {
	return kerberosString(name)
}

func kerberosTime(t time.Time) []byte {
	return berTLV(0x18, []byte(t.UTC().Format("20060102150405")+"Z"))
}

func berInt(value int) []byte {
	if value == 0 {
		return berTLV(0x02, []byte{0x00})
	}
	var body []byte
	v := uint64(value)
	for v > 0 {
		body = append([]byte{byte(v & 0xff)}, body...)
		v >>= 8
	}
	if body[0]&0x80 != 0 {
		body = append([]byte{0x00}, body...)
	}
	return berTLV(0x02, body)
}

func kerberosEncryptedData(etype int, cipherBytes []byte) []byte {
	body := berTLV(0xa0, berInt(etype))
	body = append(body, berTLV(0xa2, berTLV(0x04, cipherBytes))...)
	return berTLV(0x30, body)
}

func kerberosTicket(realmName string, snameStrs []string, etype int, cipherBytes []byte) []byte {
	body := berTLV(0xa0, berInt(5))
	body = append(body, berTLV(0xa1, kerberosRealm(realmName))...)
	body = append(body, berTLV(0xa2, kerberosPrincipalName(2, snameStrs))...)
	body = append(body, berTLV(0xa3, kerberosEncryptedData(etype, cipherBytes))...)
	return berTLV(0x61, berTLV(0x30, body))
}

func kerberosKDCReqBody(isASReq bool, cnameStrs []string, realmName string, snameStrs []string, till time.Time, nonce int, etypes []int) []byte {
	body := berTLV(0xa0, berTLV(0x03, []byte{0x00, 0x00, 0x00, 0x00}))
	if isASReq {
		body = append(body, berTLV(0xa1, kerberosPrincipalName(1, cnameStrs))...)
	}
	body = append(body, berTLV(0xa2, kerberosRealm(realmName))...)
	body = append(body, berTLV(0xa3, kerberosPrincipalName(2, snameStrs))...)
	body = append(body, berTLV(0xa5, kerberosTime(till))...)
	body = append(body, berTLV(0xa7, berInt(nonce))...)
	var etypeBody []byte
	for _, e := range etypes {
		etypeBody = append(etypeBody, berInt(e)...)
	}
	body = append(body, berTLV(0xa8, berTLV(0x30, etypeBody))...)
	return berTLV(0x30, body)
}

func kerberosKDCReq(appTag byte, msgType int, isASReq bool, cnameStrs []string, realmName string, snameStrs []string, till time.Time, nonce int, etypes []int) []byte {
	body := berTLV(0xa1, berInt(5))
	body = append(body, berTLV(0xa2, berInt(msgType))...)
	body = append(body, berTLV(0xa4, kerberosKDCReqBody(isASReq, cnameStrs, realmName, snameStrs, till, nonce, etypes))...)
	return berTLV(appTag, berTLV(0x30, body))
}

func kerberosKDCRep(appTag byte, msgType int, crealmName string, cnameStrs []string, snameStrs []string, ticketEtype int, ticketCipher []byte, encPartEtype int, encPartCipher []byte) []byte {
	body := berTLV(0xa0, berInt(5))
	body = append(body, berTLV(0xa1, berInt(msgType))...)
	body = append(body, berTLV(0xa3, kerberosRealm(crealmName))...)
	body = append(body, berTLV(0xa4, kerberosPrincipalName(1, cnameStrs))...)
	body = append(body, berTLV(0xa5, kerberosTicket(crealmName, snameStrs, ticketEtype, ticketCipher))...)
	body = append(body, berTLV(0xa6, kerberosEncryptedData(encPartEtype, encPartCipher))...)
	return berTLV(appTag, berTLV(0x30, body))
}

// ── PCAP generators ───────────────────────────────────────────────────────────

func kerberosFillerCipher(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func PCAPASREPRoasting(runID, attackerIP, targetIP, realmName, userPrincipal string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPASREPRoasting attacker=%s target=%s user=%s", attackerIP, targetIP, userPrincipal)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	till := time.Now().Add(10 * time.Hour)
	nonce := rand.Intn(1<<31 - 1)

	asReq := kerberosKDCReq(0x6a, 10, true, []string{userPrincipal}, realmName, []string{"krbtgt", realmName}, till, nonce, []int{18, 17, 23})
	reqFrame := buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 17, buildUDPDatagram(srcPort, 88, asReq)))

	asRep := kerberosKDCRep(0x6b, 11, realmName, []string{userPrincipal}, []string{"krbtgt", realmName}, 23, kerberosFillerCipher(32), 23, kerberosFillerCipher(64))
	repFrame := buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 17, buildUDPDatagram(88, srcPort, asRep)))

	frames := [][]byte{reqFrame, repFrame}
	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "asrep_roasting", finalFrames, defaultDuration)
	logInfo("Return from PCAPASREPRoasting frames=%d path=%s", len(finalFrames), path)
	return path, err
}

func PCAPGoldenTicket(runID, attackerIP, targetIP, realmName, userPrincipal string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPGoldenTicket attacker=%s target=%s user=%s", attackerIP, targetIP, userPrincipal)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	krbPort := randomPort()
	till := time.Now().Add(10 * 365 * 24 * time.Hour)
	nonce := rand.Intn(1<<31 - 1)

	tgsReq := kerberosKDCReq(0x6c, 12, false, nil, realmName, []string{"cifs", targetIP}, till, nonce, []int{23})
	reqFrame := buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 17, buildUDPDatagram(krbPort, 88, tgsReq)))

	tgsRep := kerberosKDCRep(0x6d, 13, realmName, []string{userPrincipal}, []string{"cifs", targetIP}, 23, kerberosFillerCipher(32), 23, kerberosFillerCipher(96))
	repFrame := buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 17, buildUDPDatagram(88, krbPort, tgsRep)))

	frames := [][]byte{reqFrame, repFrame}

	smbSrcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()
	syn := buildTCPSegment(smbSrcPort, 445, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	clientSeq++
	synAck := buildTCPSegment(445, smbSrcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	serverSeq++
	ack := buildTCPSegment(smbSrcPort, 445, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))
	neg := buildTCPSegment(smbSrcPort, 445, 0x18, clientSeq, serverSeq, smbNegotiatePDU[:])
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, neg)))
	clientSeq += uint32(len(smbNegotiatePDU))
	negResp := buildTCPSegment(445, smbSrcPort, 0x18, serverSeq, clientSeq, SMB2_Negotiate_Response)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, negResp)))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "golden_ticket", finalFrames, defaultDuration)
	logInfo("Return from PCAPGoldenTicket frames=%d path=%s", len(finalFrames), path)
	return path, err
}

func PCAPPassTheTicket(runID, attackerIP, targetIP, realmName, userPrincipal string) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPPassTheTicket attacker=%s target=%s user=%s", attackerIP, targetIP, userPrincipal)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	krbPort := randomPort()
	till := time.Now().Add(8 * time.Hour)
	nonce := rand.Intn(1<<31 - 1)

	tgsReq := kerberosKDCReq(0x6c, 12, false, nil, realmName, []string{"cifs", targetIP}, till, nonce, []int{18, 17, 23})
	reqFrame := buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 17, buildUDPDatagram(krbPort, 88, tgsReq)))

	tgsRep := kerberosKDCRep(0x6d, 13, realmName, []string{userPrincipal}, []string{"cifs", targetIP}, 18, kerberosFillerCipher(32), 18, kerberosFillerCipher(80))
	repFrame := buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 17, buildUDPDatagram(88, krbPort, tgsRep)))

	frames := [][]byte{reqFrame, repFrame}

	smbSrcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()
	syn := buildTCPSegment(smbSrcPort, 445, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	clientSeq++
	synAck := buildTCPSegment(445, smbSrcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	serverSeq++
	ack := buildTCPSegment(smbSrcPort, 445, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))
	neg := buildTCPSegment(smbSrcPort, 445, 0x18, clientSeq, serverSeq, smbNegotiatePDU[:])
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, neg)))
	clientSeq += uint32(len(smbNegotiatePDU))
	negResp := buildTCPSegment(445, smbSrcPort, 0x18, serverSeq, clientSeq, SMB2_Negotiate_Response)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, negResp)))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "pass_the_ticket", finalFrames, defaultDuration)
	logInfo("Return from PCAPPassTheTicket frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// ── 802.1Q VLAN double-tagging ────────────────────────────────────────────────

// buildDot1QTag builds a single 4-byte 802.1Q tag: 2-byte TPID (0x8100) +
// 2-byte TCI (3-bit priority, 1-bit DEI, 12-bit VLAN ID).
func buildDot1QTag(vlanID uint16, priority uint8) []byte {
	tci := (uint16(priority&0x7) << 13) | (vlanID & 0x0FFF)
	tag := make([]byte, 4)
	binary.BigEndian.PutUint16(tag[0:2], 0x8100)
	binary.BigEndian.PutUint16(tag[2:4], tci)
	return tag
}

// buildDoubleTaggedFrame builds a VLAN-hopping double-tagged Ethernet
// frame: dst MAC + src MAC, then an outer 802.1Q tag (the VLAN the
// attacker's port is actually on — the one the first switch strips),
// then an inner 802.1Q tag (the target VLAN — what the next switch sees
// and forwards on, having already stripped what it believes was the only
// tag), then the real EtherType and payload. This is genuinely different
// framing from buildEthernetFrame (which has no room for VLAN tags at
// all), not a variant of it.
func buildDoubleTaggedFrame(srcMAC, dstMAC [6]byte, outerVLAN, innerVLAN uint16, innerEtherType uint16, payload []byte) []byte {
	frame := make([]byte, 0, 12+4+4+2+len(payload))
	frame = append(frame, dstMAC[:]...)
	frame = append(frame, srcMAC[:]...)
	frame = append(frame, buildDot1QTag(outerVLAN, 0)...)
	frame = append(frame, buildDot1QTag(innerVLAN, 0)...)
	etBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(etBuf, innerEtherType)
	frame = append(frame, etBuf...)
	frame = append(frame, payload...)
	return frame
}

// PCAPVLANHopping generates double-tagged 802.1Q frames carrying TCP traffic
// toward multiple hosts on the target VLAN, demonstrating the attacker
// accessing hosts they are not authorized to reach via VLAN hopping.
func PCAPVLANHopping(runID, attackerIP, targetVLANGateway string, outerVLAN, innerVLAN uint16) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPVLANHopping attacker=%s outerVLAN=%d innerVLAN=%d", attackerIP, outerVLAN, innerVLAN)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}

	// Multiple target hosts on the target VLAN — attacker shouldn't be
	// able to reach any of these from their native VLAN
	targetHosts := []struct {
		ip   string
		port uint16
		mac  [6]byte
	}{
		{targetVLANGateway, 80, [6]byte{0x00, 0xBB, 0x11, 0x22, 0x33, 0x01}},
		{incrementIP(targetVLANGateway, 1), 443, [6]byte{0x00, 0xBB, 0x11, 0x22, 0x33, 0x02}},
		{incrementIP(targetVLANGateway, 2), 22, [6]byte{0x00, 0xBB, 0x11, 0x22, 0x33, 0x03}},
		{incrementIP(targetVLANGateway, 3), 3389, [6]byte{0x00, 0xBB, 0x11, 0x22, 0x33, 0x04}},
	}

	var frames [][]byte

	// Switch MAC — represents the trunk port forwarding the stripped frame
	switchMAC := [6]byte{0x00, 0xCC, 0x11, 0x22, 0x33, 0x01}

	for _, target := range targetHosts {
		srcPort := randomPort()
		seq := rand.Uint32()
		serverSeq := rand.Uint32()

		// Step 1: Attacker → Switch: double-tagged SYN
		// Outer tag = attacker's native VLAN (100), inner tag = target VLAN (200)
		syn := buildTCPSegment(srcPort, target.port, 0x02, seq, 0, nil)
		synIP := buildIPv4Packet(attackerIP, target.ip, 6, syn)
		synDoubleTagged := buildDoubleTaggedFrame(srcMAC, dstMAC, outerVLAN, innerVLAN, 0x0800, synIP)
		frames = append(frames, synDoubleTagged)

		// Step 2: Switch → Target: outer tag stripped, inner tag (VLAN 200) remains
		// This is the exploit — switch forwards frame into target VLAN
		synSingleTagged := buildSingleTaggedFrame(switchMAC, target.mac, innerVLAN, 0x0800, synIP)
		frames = append(frames, synSingleTagged)

		// Step 3: Target → Switch: untagged SYN-ACK (target is native on VLAN 200)
		synAck := buildTCPSegment(target.port, srcPort, 0x12, serverSeq, seq+1, nil)
		synAckIP := buildIPv4Packet(target.ip, attackerIP, 6, synAck)
		synAckFrame := buildEthernetFrame(target.mac, switchMAC, synAckIP)
		frames = append(frames, synAckFrame)

		// Step 4: Attacker → Switch: double-tagged ACK completing handshake
		ack := buildTCPSegment(srcPort, target.port, 0x10, seq+1, serverSeq+1, nil)
		ackIP := buildIPv4Packet(attackerIP, target.ip, 6, ack)
		ackDoubleTagged := buildDoubleTaggedFrame(srcMAC, dstMAC, outerVLAN, innerVLAN, 0x0800, ackIP)
		frames = append(frames, ackDoubleTagged)

		// Step 5: Switch → Target: outer tag stripped, ACK forwarded into target VLAN
		ackSingleTagged := buildSingleTaggedFrame(switchMAC, target.mac, innerVLAN, 0x0800, ackIP)
		frames = append(frames, ackSingleTagged)
	}
	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "vlan_hopping", finalFrames, defaultDuration)
	logInfo("Return from PCAPVLANHopping frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// buildSingleTaggedFrame builds a single 802.1Q tagged Ethernet frame —
// used to show the switch forwarding the inner-tagged frame after stripping
// the outer tag during VLAN hopping.
func buildSingleTaggedFrame(srcMAC, dstMAC [6]byte, vlanID uint16, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 0, 12+4+2+len(payload))
	frame = append(frame, dstMAC[:]...)
	frame = append(frame, srcMAC[:]...)
	frame = append(frame, buildDot1QTag(vlanID, 0)...)
	etBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(etBuf, etherType)
	frame = append(frame, etBuf...)
	frame = append(frame, payload...)
	return frame
}

// ── BGP (RFC 4271) ────────────────────────────────────────────────────────────

// bgpHeader prepends the 19-byte common BGP header (16-byte all-0xff
// Marker, 2-byte total message Length, 1-byte Type) to the given
// type-specific body.
func bgpHeader(msgType byte, body []byte) []byte {
	marker := make([]byte, 16)
	for i := range marker {
		marker[i] = 0xff
	}
	totalLen := uint16(19 + len(body))
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, totalLen)
	msg := append(append(marker, lenBuf...), msgType)
	return append(msg, body...)
}

// bgpOpen builds a BGP OPEN message (type 1): version(1)=4, My Autonomous
// System(2), Hold Time(2), BGP Identifier(4, the speaker's router ID as an
// IPv4 address), Opt Parm Len(1)=0 (capabilities omitted).
func bgpOpen(myAS uint16, holdTime uint16, bgpID string) []byte {
	body := []byte{4} // version 4
	asBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(asBuf, myAS)
	body = append(body, asBuf...)
	holdBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(holdBuf, holdTime)
	body = append(body, holdBuf...)
	body = append(body, dhcpIPv4Bytes(bgpID)...)
	body = append(body, 0x00) // Opt Parm Len = 0
	return bgpHeader(1, body)
}

// bgpKeepalive builds a BGP KEEPALIVE message (type 4): header only, empty body.
func bgpKeepalive() []byte {
	return bgpHeader(4, nil)
}

// bgpEncodePrefix encodes an IPv4 CIDR prefix as BGP NLRI: 1-byte prefix
// length in bits, followed by ceil(bits/8) significant address bytes
// (RFC 4271 §4.3 — not the full 4 bytes regardless of prefix length).
func bgpEncodePrefix(cidr string) ([]byte, error) {
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("bgpEncodePrefix: invalid CIDR %q (missing '/')", cidr)
	}
	ip := parts[0]
	var bits int
	if _, err := fmt.Sscanf(parts[1], "%d", &bits); err != nil {
		return nil, fmt.Errorf("bgpEncodePrefix: invalid prefix length in %q: %v", cidr, err)
	}
	full := dhcpIPv4Bytes(ip)
	needed := (bits + 7) / 8
	if needed > 4 {
		needed = 4
	}
	return append([]byte{byte(bits)}, full[:needed]...), nil
}

// bgpUpdate builds a BGP UPDATE message (type 2) announcing the given
// prefix with the given AS_PATH (a single AS_SEQUENCE segment) and
// NEXT_HOP, and no withdrawn routes. Path attribute flags (0x40 = Well-
// known, Transitive, Complete) and the ORIGIN=INCOMPLETE(2)/AS_PATH/
// NEXT_HOP attribute set match the structure independently confirmed
// against a real annotated BGP UPDATE capture (vendor documentation
// trace), not just the RFC text.
func bgpUpdate(prefixCIDR string, asPath []uint16, nextHop string) ([]byte, error) {
	prefix, err := bgpEncodePrefix(prefixCIDR)
	if err != nil {
		return nil, err
	}

	origin := []byte{0x40, 1, 1, 2} // flags, type=ORIGIN(1), len=1, value=INCOMPLETE(2)

	var asPathSegBody []byte
	for _, asn := range asPath {
		asnBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(asnBuf, asn)
		asPathSegBody = append(asPathSegBody, asnBuf...)
	}
	asPathSeg := append([]byte{2, byte(len(asPath))}, asPathSegBody...) // segment type 2 = AS_SEQUENCE
	asPathAttr := append([]byte{0x40, 2, byte(len(asPathSeg))}, asPathSeg...)

	nextHopAttr := append([]byte{0x40, 3, 4}, dhcpIPv4Bytes(nextHop)...)

	pathAttrs := append(append(append([]byte{}, origin...), asPathAttr...), nextHopAttr...)

	withdrawnLenBuf := []byte{0x00, 0x00} // no withdrawn routes
	pathAttrLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pathAttrLenBuf, uint16(len(pathAttrs)))

	body := append(append([]byte{}, withdrawnLenBuf...), pathAttrLenBuf...)
	body = append(body, pathAttrs...)
	body = append(body, prefix...)

	return bgpHeader(2, body), nil
}

// PCAPBGPHijack generates a minimal real BGP session leading up to the
// malicious UPDATE: TCP handshake on port 179, OPEN/OPEN, KEEPALIVE/
// KEEPALIVE, then the attacker's UPDATE announcing the hijacked prefix
// with the syslog's claimed AS_PATH and a NEXT_HOP of the attacker's own
// IP — matching runBGPHijack's single-flow (attacker -> router, port 179)
// telemetry shape.
func PCAPBGPHijack(runID, attackerIP, routerIP, prefixCIDR string, hijackAS uint16) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPBGPHijack attacker=%s router=%s prefix=%s as=%d", attackerIP, routerIP, prefixCIDR, hijackAS)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()
	var frames [][]byte

	syn := buildTCPSegment(srcPort, 179, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, routerIP, 6, syn)))
	clientSeq++
	synAck := buildTCPSegment(179, srcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(routerIP, attackerIP, 6, synAck)))
	serverSeq++
	ack := buildTCPSegment(srcPort, 179, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, routerIP, 6, ack)))

	openMsg := bgpOpen(hijackAS, 180, attackerIP)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, routerIP, 6, buildTCPSegment(srcPort, 179, 0x18, clientSeq, serverSeq, openMsg))))
	clientSeq += uint32(len(openMsg))
	openResp := bgpOpen(65000, 180, routerIP) // legitimate router's own AS (65000, per runBGPHijack's syslog: "expected via AS65000")
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(routerIP, attackerIP, 6, buildTCPSegment(179, srcPort, 0x18, serverSeq, clientSeq, openResp))))
	serverSeq += uint32(len(openResp))

	keepalive1 := bgpKeepalive()
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, routerIP, 6, buildTCPSegment(srcPort, 179, 0x18, clientSeq, serverSeq, keepalive1))))
	clientSeq += uint32(len(keepalive1))
	keepalive2 := bgpKeepalive()
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(routerIP, attackerIP, 6, buildTCPSegment(179, srcPort, 0x18, serverSeq, clientSeq, keepalive2))))
	serverSeq += uint32(len(keepalive2))

	updateMsg, err := bgpUpdate(prefixCIDR, []uint16{hijackAS}, attackerIP)
	if err != nil {
		logError("PCAPBGPHijack bgpUpdate: %v", err)
		bgFrames := generateBackgroundTraffic(getAllDevices())
		finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
		path, werr := writePCAPFile(runID, "bgp_hijack", finalFrames, defaultDuration)
		return path, werr
	}
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, routerIP, 6, buildTCPSegment(srcPort, 179, 0x18, clientSeq, serverSeq, updateMsg))))
	clientSeq += uint32(len(updateMsg))
	finalAck := buildTCPSegment(179, srcPort, 0x10, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(routerIP, attackerIP, 6, finalAck)))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "bgp_hijack", finalFrames, defaultDuration)
	logInfo("Return from PCAPBGPHijack frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// buildTLSExtensionSNI builds the Server Name Indication extension
// (type 0x0000) carrying a single host_name entry for the given domain.
func buildTLSExtensionSNI(serverName string) []byte {
	nameBytes := []byte(serverName)
	entry := make([]byte, 0, 3+len(nameBytes))
	entry = append(entry, 0x00) // name_type: host_name
	entry = append(entry, byte(len(nameBytes)>>8), byte(len(nameBytes)))
	entry = append(entry, nameBytes...)

	listLen := len(entry)
	extData := make([]byte, 0, 2+listLen)
	extData = append(extData, byte(listLen>>8), byte(listLen))
	extData = append(extData, entry...)

	ext := make([]byte, 0, 4+len(extData))
	ext = append(ext, 0x00, 0x00) // extension_type: server_name
	ext = append(ext, byte(len(extData)>>8), byte(len(extData)))
	ext = append(ext, extData...)
	return ext
}

// buildTLSClientHelloSNI builds a structurally valid TLS ClientHello carrying
// a Server Name Indication extension. Needed for DomainFronting, where the
// SNI value (the legitimate-looking front domain) is the entire point of
// the attack and must be visible on the wire — otherwise identical to
// buildMinimalTLSClientHello, which has no extensions at all.
func buildTLSClientHelloSNI(serverName string) []byte {
	random := make([]byte, 32)
	rand.Read(random)

	sniExt := buildTLSExtensionSNI(serverName)

	body := make([]byte, 0, 40+len(sniExt))
	body = append(body, 0x03, 0x03) // client_version: TLS 1.2
	body = append(body, random...)
	body = append(body, 0x00)       // session_id length: 0
	body = append(body, 0x00, 0x02) // cipher_suites length: 2 bytes
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01)       // compression_methods length: 1
	body = append(body, 0x00)       // compression method: null
	body = append(body, byte(len(sniExt)>>8), byte(len(sniExt)))
	body = append(body, sniExt...)

	handshake := make([]byte, 0, len(body)+4)
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := make([]byte, 0, len(handshake)+5)
	record = append(record, 0x16, 0x03, 0x01) // Handshake, TLS 1.0 record version
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

// buildMinimalTLSServerHello builds a structurally valid ServerHello with
// the same negotiated cipher suite buildMinimalTLSClientHello/
// buildTLSClientHelloSNI offer.
func buildMinimalTLSServerHello() []byte {
	random := make([]byte, 32)
	rand.Read(random)

	body := make([]byte, 0, 40)
	body = append(body, 0x03, 0x03) // server_version: TLS 1.2
	body = append(body, random...)
	body = append(body, 0x00)       // session_id length: 0
	body = append(body, 0x13, 0x01) // cipher_suite chosen
	body = append(body, 0x00)       // compression method: null
	body = append(body, 0x00, 0x00) // extensions length: 0

	handshake := make([]byte, 0, len(body)+4)
	handshake = append(handshake, 0x02) // ServerHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := make([]byte, 0, len(handshake)+5)
	record = append(record, 0x16, 0x03, 0x03) // Handshake, TLS 1.2 record version
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

// buildTLSApplicationData wraps arbitrary bytes in a TLS Application Data
// record (type 0x17). The payload isn't actually encrypted — Wireshark has
// no key material for real captures either, so any well-framed Application
// Data record displays identically: opaque bytes, not a parse error. This
// is what lets us represent "encrypted C2/exfil traffic" without a real
// TLS implementation.
func buildTLSApplicationData(payload []byte) []byte {
	record := make([]byte, 0, 5+len(payload))
	record = append(record, 0x17, 0x03, 0x03)
	record = append(record, byte(len(payload)>>8), byte(len(payload)))
	record = append(record, payload...)
	return record
}

// PCAPTLSExchange generates a minimal real TLS handshake (ClientHello
// carrying the given SNI, then ServerHello) followed by one Application
// Data record each direction carrying requestPayload/responsePayload as
// opaque bytes. Used for HTTPS-based C2/exfil attacks (PowerShellC2,
// WebSocketC2, DomainFronting) — writing plaintext bytes directly on
// port 443 via PCAPGenericTCPExchange would make Wireshark try (and fail)
// to decode them as TLS, since port 443 is mapped to the TLS dissector.
func PCAPTLSExchange(runID, attackName, attackerIP, targetIP string, targetPort uint16, sni string, requestPayload, responsePayload []byte) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPTLSExchange attack=%s attacker=%s target=%s port=%d sni=%s", attackName, attackerIP, targetIP, targetPort, sni)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()
	var frames [][]byte

	syn := buildTCPSegment(srcPort, targetPort, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	clientSeq++
	synAck := buildTCPSegment(targetPort, srcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	serverSeq++
	ack := buildTCPSegment(srcPort, targetPort, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

	clientHello := buildTLSClientHelloSNI(sni)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, targetPort, 0x18, clientSeq, serverSeq, clientHello))))
	clientSeq += uint32(len(clientHello))

	serverHello := buildMinimalTLSServerHello()
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(targetPort, srcPort, 0x18, serverSeq, clientSeq, serverHello))))
	serverSeq += uint32(len(serverHello))

	midAck := buildTCPSegment(srcPort, targetPort, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, midAck)))

	if len(requestPayload) > 0 {
		appData := buildTLSApplicationData(requestPayload)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, targetPort, 0x18, clientSeq, serverSeq, appData))))
		clientSeq += uint32(len(appData))
	}
	if len(responsePayload) > 0 {
		appData := buildTLSApplicationData(responsePayload)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(targetPort, srcPort, 0x18, serverSeq, clientSeq, appData))))
		serverSeq += uint32(len(appData))
	}

	finalAck := buildTCPSegment(srcPort, targetPort, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, finalAck)))

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, attackName, finalFrames, defaultDuration)
	logInfo("Return from PCAPTLSExchange frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPSSLRenegotiationExhaustion generates a TLS session followed by repeated
// ClientHello renegotiation requests — the CPU-exhaustion pattern where the
// attacker forces the server to perform expensive key exchange repeatedly.
func PCAPSSLRenegotiationExhaustion(runID, attackerIP, targetIP string, targetPort uint16, renegotiations int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPSSLRenegotiationExhaustion attacker=%s target=%s reneg=%d", attackerIP, targetIP, renegotiations)

	srcMAC := parseMACAddress("00:AA:11:22:33:44")
	dstMAC := parseMACAddress("00:AA:BB:CC:DD:01")
	srcPort := randomPort()
	var seq, ack uint32 = 1000, 0
	var frames [][]byte

	// --- Initial TCP handshake ---
	// SYN
	syn := buildTCPSegment(srcPort, targetPort, 0x02, seq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	seq++
	// SYN-ACK (server)
	synAck := buildTCPSegment(targetPort, srcPort, 0x12, 5000, seq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	ack = 5001
	// ACK
	ackSeg := buildTCPSegment(srcPort, targetPort, 0x10, seq, ack, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ackSeg)))

	// --- Initial ClientHello ---
	hello := buildMinimalTLSClientHello()
	tlsPush := buildTCPSegment(srcPort, targetPort, 0x18, seq, ack, hello) // PSH+ACK
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, tlsPush)))
	seq += uint32(len(hello))

	// Minimal ServerHello ACK back
	srvHello := buildMinimalTLSServerHello()
	srvPush := buildTCPSegment(targetPort, srcPort, 0x18, ack, seq, srvHello)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, srvPush)))
	ack += uint32(len(srvHello))

	// Client ACKs the ServerHello
	ackSeg2 := buildTCPSegment(srcPort, targetPort, 0x10, seq, ack, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ackSeg2)))

	// --- Renegotiation loop: attacker hammers repeated ClientHellos ---
	// Each one forces a full key-exchange on the server side — that's the attack.
	for i := 0; i < renegotiations; i++ {
		reHello := buildMinimalTLSClientHello()
		rePush := buildTCPSegment(srcPort, targetPort, 0x18, seq, ack, reHello)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, rePush)))
		seq += uint32(len(reHello))

		// Server sends an ACK back (acknowledging receipt, starting expensive key exchange)
		srvAck := buildTCPSegment(targetPort, srcPort, 0x10, ack, seq, nil)
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, srvAck)))
	}

	bgFrames := generateBackgroundTrafficN(getAllDevices(), renegotiations/2+10)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "ssl_renegotiation_exhaustion", finalFrames, defaultDuration)
	logInfo("Return from PCAPSSLRenegotiationExhaustion frames=%d path=%s", len(finalFrames), path)
	return path, err
}

func buildLDAPBindRequest(baseDN string) []byte {
	buf := make([]byte, 0, 30)
	// SEQUENCE { messageID, BindRequest }
	buf = append(buf, 0x30) // SEQUENCE
	buf = append(buf, 12)   // length: 12 bytes exactly

	// MessageID INTEGER 1
	buf = append(buf, 0x02, 0x01, 0x01)

	// BindRequest [0]
	buf = append(buf, 0x60) // context [0]
	buf = append(buf, 7)    // length: 7 bytes

	// Version INTEGER 3
	buf = append(buf, 0x02, 0x01, 0x03)

	// Name OCTET STRING (empty for anonymous)
	buf = append(buf, 0x04, 0x00)

	// Auth [0] (empty for anonymous simple auth)
	buf = append(buf, 0x80, 0x00)

	return buf
}

func buildLDAPBindResponse() []byte {
	buf := make([]byte, 0, 30)
	buf = append(buf, 0x30) // SEQUENCE
	buf = append(buf, 12)   // length: 12 bytes

	// MessageID INTEGER 1
	buf = append(buf, 0x02, 0x01, 0x01)

	// BindResponse [1]
	buf = append(buf, 0x61) // context [1]
	buf = append(buf, 7)    // length: 7 bytes

	// ResultCode ENUMERATED 0 (success)
	buf = append(buf, 0x0A, 0x01, 0x00)

	// MatchedDN OCTET STRING (empty)
	buf = append(buf, 0x04, 0x00)

	// DiagnosticMessage OCTET STRING (empty)
	buf = append(buf, 0x04, 0x00)

	return buf
}

func buildLDAPSearchRequest(baseDN string) []byte {
	buf := make([]byte, 0, 100)

	// SEQUENCE
	buf = append(buf, 0x30)

	// Reserve space for length (will fill later)
	lenPos := len(buf)
	buf = append(buf, 0x00)

	// MessageID INTEGER 2
	buf = append(buf, 0x02, 0x01, 0x02)

	// SearchRequest [3]
	buf = append(buf, 0x63)
	searchLenPos := len(buf)
	buf = append(buf, 0x00) // Reserve for search length

	// BaseObject OCTET STRING
	dnBytes := []byte(baseDN)
	buf = append(buf, 0x04, byte(len(dnBytes)))
	buf = append(buf, dnBytes...)

	// Scope ENUMERATED 2 (wholeSubtree)
	buf = append(buf, 0x0A, 0x01, 0x02)

	// DerefAliases ENUMERATED 0
	buf = append(buf, 0x0A, 0x01, 0x00)

	// SizeLimit INTEGER 0
	buf = append(buf, 0x02, 0x01, 0x00)

	// TimeLimit INTEGER 0
	buf = append(buf, 0x02, 0x01, 0x00)

	// TypesOnly BOOLEAN FALSE
	buf = append(buf, 0x01, 0x01, 0x00)

	// Filter: present [7] objectClass
	buf = append(buf, 0xA7, 0x0B)
	buf = append(buf, []byte("objectClass")...)

	// Fill in SearchRequest length
	searchLen := len(buf) - searchLenPos - 1
	buf[searchLenPos] = byte(searchLen)

	// Fill in SEQUENCE length
	seqLen := len(buf) - lenPos - 1
	buf[lenPos] = byte(seqLen)

	return buf
}

// buildLDAPSearchResponse builds a minimal LDAP Search response with results
func buildLDAPSearchResponse(count int) []byte {
	buf := make([]byte, 0, 200)

	// SEQUENCE
	buf = append(buf, 0x30, 150)

	// MessageID (INTEGER 2)
	buf = append(buf, 0x02, 0x01, 0x02)

	// SearchResultEntry [4] (simplified - just one entry)
	buf = append(buf, 0x64, 100)

	// ObjectName (OCTET STRING) - example user DN
	userDN := fmt.Sprintf("cn=user%d,dc=corp,dc=local", count)
	buf = append(buf, 0x04, byte(len(userDN)))
	buf = append(buf, []byte(userDN)...)

	// Attributes (SET OF)
	buf = append(buf, 0x30, 50)

	// Attribute: cn
	buf = append(buf, 0x30, 20)
	buf = append(buf, 0x04, 0x02)
	buf = append(buf, []byte("cn")...)
	buf = append(buf, 0x31, 15)
	buf = append(buf, 0x04, byte(len(userDN)))
	buf = append(buf, []byte(userDN)...)

	for len(buf) < 180 {
		buf = append(buf, 0x00)
	}

	return buf
}

// buildTLSServerHelloCertificate builds ServerHello + Certificate in one TLS record
func buildTLSServerHelloCertificate() []byte {
	// --- ServerHello ---
	sh := []byte{
		// Handshake: ServerHello (type 0x02)
		0x02,
		0x00, 0x00, 0x46, // length 70
		0x03, 0x03, // TLS 1.2
	}
	// 32 bytes server random
	serverRandom := make([]byte, 32)
	for i := range serverRandom {
		serverRandom[i] = byte(rand.Intn(256))
	}
	sh = append(sh, serverRandom...)
	// Session ID length 0
	sh = append(sh, 0x00)
	// Cipher suite TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C)
	sh = append(sh, 0x00, 0x9C)
	// Compression method null
	sh = append(sh, 0x00)
	// Extensions length
	sh = append(sh, 0x00, 0x0E)
	// Renegotiation info extension
	sh = append(sh, 0xFF, 0x01, 0x00, 0x01, 0x00)
	// EC point formats
	sh = append(sh, 0x00, 0x0B, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02)
	// Heartbeat extension (mode: peer_allowed_to_send = 1)
	sh = append(sh, 0x00, 0x0F, 0x00, 0x01, 0x01)

	// --- Certificate ---
	// Fake self-signed cert (minimal DER structure)
	certDER := make([]byte, 256)
	// ASN.1 SEQUENCE
	certDER[0] = 0x30
	certDER[1] = 0x82
	certDER[2] = 0x00
	certDER[3] = 0xFC // length 252
	// Version
	certDER[4] = 0xA0
	certDER[5] = 0x03
	certDER[6] = 0x02
	certDER[7] = 0x01
	certDER[8] = 0x02 // v3
	// Serial number
	certDER[9] = 0x02
	certDER[10] = 0x08
	for i := 11; i < 19; i++ {
		certDER[i] = byte(rand.Intn(256))
	}
	// Issuer CN=corp.local (simplified)
	cn := []byte("CN=*.corp.local")
	copy(certDER[40:], cn)

	certLen := len(certDER)
	cert := []byte{
		0x0B, // Handshake: Certificate
		byte((certLen + 6) >> 16), byte((certLen + 6) >> 8), byte(certLen + 6),
		// Certificates length
		byte((certLen + 3) >> 16), byte((certLen + 3) >> 8), byte(certLen + 3),
		// Certificate length
		byte(certLen >> 16), byte(certLen >> 8), byte(certLen),
	}
	cert = append(cert, certDER...)

	// Combine into one TLS Handshake record
	handshake := append(sh, cert...)
	rec := []byte{
		0x16,       // ContentType: Handshake
		0x03, 0x03, // TLS 1.2
		byte(len(handshake) >> 8), byte(len(handshake)),
	}
	rec = append(rec, handshake...)
	return rec
}

// buildTLSHeartbeatRequest builds a Heartbleed probe
func buildTLSHeartbeatRequest() []byte {
	payload := []byte{
		0x01,       // HeartbeatType: request
		0x00, 0x05, // Payload length: 5 (actual)
	}
	// 5 bytes actual payload
	payload = append(payload, 0x41, 0x41, 0x41, 0x41, 0x41)
	// 16 bytes padding (required by RFC 6520)
	padding := make([]byte, 16)
	for i := range padding {
		padding[i] = byte(rand.Intn(256))
	}
	payload = append(payload, padding...)

	rec := []byte{
		0x18,       // ContentType: Heartbeat
		0x03, 0x03, // TLS 1.2
		byte(len(payload) >> 8), byte(len(payload)),
	}
	rec = append(rec, payload...)
	return rec
}

// buildTLSHeartbeatResponse builds a Heartbleed response (server leaks memory - response much larger than request)
func buildTLSHeartbeatResponse() []byte {
	// Heartbleed signature: response payload much larger than request payload
	leakedSize := 256
	payload := []byte{
		0x02,                                    // HeartbeatType: response
		byte(leakedSize >> 8), byte(leakedSize), // Payload length: 256
	}
	// Leaked memory (256 bytes)
	leaked := make([]byte, leakedSize)
	for i := range leaked {
		leaked[i] = byte(rand.Intn(256))
	}
	payload = append(payload, leaked...)
	// 16 bytes padding
	padding := make([]byte, 16)
	for i := range padding {
		padding[i] = byte(rand.Intn(256))
	}
	payload = append(payload, padding...)

	rec := []byte{
		0x18,       // ContentType: Heartbeat
		0x03, 0x03, // TLS 1.2
		byte(len(payload) >> 8), byte(len(payload)),
	}
	rec = append(rec, payload...)
	return rec
}

// buildTLSPaddingOracleProbe builds a crafted encrypted record for padding oracle test
func buildTLSPaddingOracleProbe() []byte {
	// Crafted CBC-encrypted record with manipulated IV/padding
	encrypted := make([]byte, 48) // 3 AES blocks
	for i := range encrypted {
		encrypted[i] = byte(rand.Intn(256))
	}
	// Manipulate last byte (padding oracle attack modifies ciphertext)
	encrypted[47] = 0x0F // Force bad padding

	rec := []byte{
		0x17,       // ContentType: Application Data
		0x03, 0x01, // TLS 1.0 (CBC vulnerable version)
		byte(len(encrypted) >> 8), byte(len(encrypted)),
	}
	rec = append(rec, encrypted...)
	return rec
}

// buildTLSAlertBadRecordMAC builds a TLS Alert for bad_record_mac (padding oracle response)
func buildTLSAlertBadRecordMAC() []byte {
	alert := []byte{
		0x02, // AlertLevel: fatal
		0x14, // AlertDescription: bad_record_mac (20)
	}
	rec := []byte{
		0x15,       // ContentType: Alert
		0x03, 0x01, // TLS 1.0
		0x00, 0x02, // length
	}
	rec = append(rec, alert...)
	return rec
}

// PCAPDNSMultiQuery generates a single PCAP containing query/response pairs
// for each domain in the list — used for subdomain enumeration, DNS recon,
// and similar attacks where many DNS lookups happen in one run.
func PCAPDNSMultiQuery(runID, attackName, clientIP, dnsIP string, domains []string, nxdomain bool) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPDNSMultiQuery attack=%s client=%s dns=%s count=%d", attackName, clientIP, dnsIP, len(domains))

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}

	qtype := uint16(0x0010) // TXT
	if !nxdomain {
		qtype = 0x0001 // A record
	}

	var frames [][]byte
	for _, domain := range domains {
		srcPort := randomPort()
		query := buildDNSQueryType(domain, qtype)
		queryFrame := buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(clientIP, dnsIP, 17, buildUDPDatagram(srcPort, 53, query)))
		frames = append(frames, queryFrame)

		response := make([]byte, len(query))
		copy(response, query)
		response[2] = 0x81
		if nxdomain {
			response[3] = 0x83
		} else {
			response[3] = 0x80
		}
		responseFrame := buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dnsIP, clientIP, 17, buildUDPDatagram(53, srcPort, response)))
		frames = append(frames, responseFrame)
	}

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, attackName, finalFrames, defaultDuration)
	logInfo("Return from PCAPDNSMultiQuery frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPHTTPMultiRequest generates a single PCAP containing one TCP handshake
// followed by multiple HTTP GET request/response pairs over the same
// connection (HTTP/1.1 keep-alive) — used for directory brute-forcing,
// web fuzzing, and similar attacks that hammer one host with many requests.
func PCAPHTTPMultiRequest(runID, attackName, clientIP, serverIP string, serverPort uint16, requests [][]byte, responses [][]byte) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPHTTPMultiRequest attack=%s client=%s server=%s count=%d", attackName, clientIP, serverIP, len(requests))

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	srcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()

	var frames [][]byte

	// TCP handshake
	syn := buildTCPSegment(srcPort, serverPort, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(clientIP, serverIP, 6, syn)))
	clientSeq++

	synAck := buildTCPSegment(serverPort, srcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(serverIP, clientIP, 6, synAck)))
	serverSeq++

	ack := buildTCPSegment(srcPort, serverPort, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(clientIP, serverIP, 6, ack)))

	// One GET/response pair per path, over the same connection
	for i := range requests {
		req := requests[i]
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(clientIP, serverIP, 6, buildTCPSegment(srcPort, serverPort, 0x18, clientSeq, serverSeq, req))))
		clientSeq += uint32(len(req))

		resp := responses[i]
		frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(serverIP, clientIP, 6, buildTCPSegment(serverPort, srcPort, 0x18, serverSeq, clientSeq, resp))))
		serverSeq += uint32(len(resp))
	}

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, attackName, finalFrames, defaultDuration)
	logInfo("Return from PCAPHTTPMultiRequest frames=%d path=%s", len(finalFrames), path)
	return path, err
}

func httpStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 301:
		return "Moved Permanently"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	default:
		return "OK"
	}
}

// incrementIP adds n to the last octet of a dotted-quad IP string.
func incrementIP(ip string, n int) string {
	var a, b, c, d int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	d += n
	if d > 254 {
		d = 254
	}
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

// ── Background Traffic ────────────────────────────────────────────────────────

// generateBackgroundTraffic builds a realistic mix of ARP, DNS, ICMP, HTTP,
// and TCP keepalive frames between real topology devices. Interleaved into
// attack PCAPs so captures don't look suspiciously traffic-free outside the
// attack itself.
func generateBackgroundTraffic(devices []*Device) [][]byte {
	if len(devices) < 2 {
		return nil
	}

	var frames [][]byte

	commonDomains := []string{
		"corp.local", "dc01.corp.local", "fileserver.corp.local",
		"mail.corp.local", "updates.corp.local", "time.corp.local",
		"printer.corp.local", "vpn.corp.local", "intranet.corp.local",
	}

	// Randomize total number of background events (10-35)
	eventCount := 10 + rand.Intn(26)

	// Weighted traffic type pool — ARP and DNS appear more often than HTTP/ICMP,
	// matching real LAN traffic distributions where ARP/DNS dominate background noise
	typePool := []int{
		0, 0, 0, 0, // ARP — 4 slots
		1, 1, 1, 1, 1, // DNS — 5 slots
		2, 2, // ICMP — 2 slots
		3, 3, // HTTP — 2 slots
		4, // keepalive — 1 slot
	}

	for i := 0; i < eventCount; i++ {
		// Pick two distinct random devices
		srcIdx := rand.Intn(len(devices))
		dstIdx := rand.Intn(len(devices))
		for dstIdx == srcIdx {
			dstIdx = rand.Intn(len(devices))
		}
		src := devices[srcIdx]
		dst := devices[dstIdx]

		srcMAC := parseMACAddress(src.MACAddress)
		dstMAC := parseMACAddress(dst.MACAddress)

		trafficType := typePool[rand.Intn(len(typePool))]

		switch trafficType {

		case 0: // ARP — occasionally skip the reply (unanswered ARP is realistic)
			broadcastMAC := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			arpReq := buildARPRequest(srcMAC, src.IPAddress, dst.IPAddress)
			reqFrame := make([]byte, 14+len(arpReq))
			copy(reqFrame[0:6], broadcastMAC[:])
			copy(reqFrame[6:12], srcMAC[:])
			binary.BigEndian.PutUint16(reqFrame[12:14], 0x0806)
			copy(reqFrame[14:], arpReq)
			frames = append(frames, reqFrame)

			if rand.Intn(4) != 0 { // 75% chance of reply
				arpReply := buildARPReply(dstMAC, srcMAC, dst.IPAddress, src.IPAddress)
				replyFrame := make([]byte, 14+len(arpReply))
				copy(replyFrame[0:6], srcMAC[:])
				copy(replyFrame[6:12], dstMAC[:])
				binary.BigEndian.PutUint16(replyFrame[12:14], 0x0806)
				copy(replyFrame[14:], arpReply)
				frames = append(frames, replyFrame)
			}

		case 1: // DNS — vary query type and domain randomly
			domain := commonDomains[rand.Intn(len(commonDomains))]
			// Occasionally add a random subdomain prefix
			if rand.Intn(3) == 0 {
				prefixes := []string{"www", "api", "mail", "vpn", "dev"}
				domain = prefixes[rand.Intn(len(prefixes))] + "." + domain
			}
			srcPort := randomPort()
			qtype := uint16(0x0001) // A
			if rand.Intn(5) == 0 {
				qtype = 0x001c // AAAA occasionally
			}
			query := buildDNSQueryType(domain, qtype)
			udpQ := buildUDPDatagram(srcPort, 53, query)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 17, udpQ)))

			// Occasionally simulate NXDOMAIN instead of successful response
			resp := make([]byte, len(query))
			copy(resp, query)
			resp[2] = 0x81
			if rand.Intn(6) == 0 {
				resp[3] = 0x83 // NXDOMAIN
			} else {
				resp[3] = 0x80
				binary.BigEndian.PutUint16(resp[6:8], 0x0001)
				answer := []byte{
					0xC0, 0x0C,
					0x00, 0x01,
					0x00, 0x01,
					0x00, 0x00, 0x01, 0x2C,
					0x00, 0x04,
					10, 0, byte(rand.Intn(5) + 1), byte(rand.Intn(200) + 10),
				}
				resp = append(resp, answer...)
			}
			udpR := buildUDPDatagram(53, srcPort, resp)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 17, udpR)))

		case 2: // ICMP — vary payload size
			id := uint16(rand.Intn(65535))
			seq := uint16(rand.Intn(512) + 1)
			payloadSize := []int{8, 16, 32, 56}[rand.Intn(4)]
			echoPayload := make([]byte, payloadSize)
			for j := range echoPayload {
				echoPayload[j] = byte('a' + j%26)
			}
			echoReq := buildICMPSegment(8, 0, 0, id, seq, echoPayload)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 1, echoReq)))

			if rand.Intn(5) != 0 { // 80% chance of reply
				echoReply := buildICMPSegment(0, 0, 0, id, seq, echoPayload)
				frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 1, echoReply)))
			}

		case 3: // HTTP — vary paths, ports, and response codes
			srcPort := randomPort()
			clientSeq := rand.Uint32()
			serverSeq := rand.Uint32()
			paths := []string{"/", "/index.html", "/api/health", "/favicon.ico", "/robots.txt", "/api/status", "/login", "/static/app.js"}
			reqPath := paths[rand.Intn(len(paths))]
			httpPort := []uint16{80, 8080, 8443}[rand.Intn(3)]
			responseCodes := []string{"200 OK", "204 No Content", "301 Moved Permanently", "304 Not Modified"}
			responseCode := responseCodes[rand.Intn(len(responseCodes))]

			syn := buildTCPSegment(srcPort, httpPort, 0x02, clientSeq, 0, nil)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 6, syn)))
			clientSeq++

			synAck := buildTCPSegment(httpPort, srcPort, 0x12, serverSeq, clientSeq, nil)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 6, synAck)))
			serverSeq++

			getPayload := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\n\r\n", reqPath, dst.IPAddress))
			get := buildTCPSegment(srcPort, httpPort, 0x18, clientSeq, serverSeq, getPayload)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 6, get)))
			clientSeq += uint32(len(getPayload))

			respBody := []byte(fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", responseCode))
			resp := buildTCPSegment(httpPort, srcPort, 0x18, serverSeq, clientSeq, respBody)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 6, resp)))

		case 4: // TCP keepalive — vary port
			srcPort := randomPort()
			ports := []uint16{80, 443, 22, 3389, 8080}
			dstPort := ports[rand.Intn(len(ports))]
			seq := rand.Uint32()
			ackVal := rand.Uint32()
			keepalive := buildTCPSegment(srcPort, dstPort, 0x10, seq-1, ackVal, nil)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 6, keepalive)))

			if rand.Intn(3) != 0 { // 67% chance of keepalive-ack
				keepaliveAck := buildTCPSegment(dstPort, srcPort, 0x10, ackVal, seq, nil)
				frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 6, keepaliveAck)))
			}
		}
	}

	return frames
}

// interleaveBackgroundTraffic spreads bgFrames evenly between attackFrames
// so background traffic lands at ~35% of the final frame count.
// Attack frame order is preserved exactly.
func interleaveBackgroundTraffic(attackFrames [][]byte, bgFrames [][]byte) [][]byte {
	if len(bgFrames) == 0 {
		return attackFrames
	}
	if len(attackFrames) == 0 {
		return bgFrames
	}

	result := make([][]byte, 0, len(attackFrames)+len(bgFrames))
	bgStep := float64(len(attackFrames)) / float64(len(bgFrames))
	bgIdx := 0
	bgThreshold := bgStep / 2

	for i, f := range attackFrames {
		for bgIdx < len(bgFrames) && float64(i) >= bgThreshold {
			result = append(result, bgFrames[bgIdx])
			bgIdx++
			bgThreshold += bgStep
		}
		result = append(result, f)
	}
	for bgIdx < len(bgFrames) {
		result = append(result, bgFrames[bgIdx])
		bgIdx++
	}

	return result
}

// generateBackgroundTrafficN is generateBackgroundTraffic with an explicit
// event count, for high-frame-count attacks (port scan, floods) where the
// default 10-35 events would be lost in thousands of attack frames.
func generateBackgroundTrafficN(devices []*Device, n int) [][]byte {
	if n < 10 {
		n = 10
	}
	if n > 500 {
		n = 500 // cap to avoid huge PCAPs
	}

	// Temporarily override the event count by calling the core logic directly
	// with n iterations instead of the default random 10-35 range.
	if len(devices) < 2 {
		return nil
	}

	var frames [][]byte

	commonDomains := []string{
		"corp.local", "dc01.corp.local", "fileserver.corp.local",
		"mail.corp.local", "updates.corp.local", "time.corp.local",
		"printer.corp.local", "vpn.corp.local", "intranet.corp.local",
	}

	typePool := []int{
		0, 0, 0, 0,
		1, 1, 1, 1, 1,
		2, 2,
		3, 3,
		4,
	}

	for i := 0; i < n; i++ {
		srcIdx := rand.Intn(len(devices))
		dstIdx := rand.Intn(len(devices))
		for dstIdx == srcIdx {
			dstIdx = rand.Intn(len(devices))
		}
		src := devices[srcIdx]
		dst := devices[dstIdx]
		srcMAC := parseMACAddress(src.MACAddress)
		dstMAC := parseMACAddress(dst.MACAddress)
		trafficType := typePool[rand.Intn(len(typePool))]

		switch trafficType {
		case 0:
			broadcastMAC := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			arpReq := buildARPRequest(srcMAC, src.IPAddress, dst.IPAddress)
			reqFrame := make([]byte, 14+len(arpReq))
			copy(reqFrame[0:6], broadcastMAC[:])
			copy(reqFrame[6:12], srcMAC[:])
			binary.BigEndian.PutUint16(reqFrame[12:14], 0x0806)
			copy(reqFrame[14:], arpReq)
			frames = append(frames, reqFrame)
			if rand.Intn(4) != 0 {
				arpReply := buildARPReply(dstMAC, srcMAC, dst.IPAddress, src.IPAddress)
				replyFrame := make([]byte, 14+len(arpReply))
				copy(replyFrame[0:6], srcMAC[:])
				copy(replyFrame[6:12], dstMAC[:])
				binary.BigEndian.PutUint16(replyFrame[12:14], 0x0806)
				copy(replyFrame[14:], arpReply)
				frames = append(frames, replyFrame)
			}
		case 1:
			domain := commonDomains[rand.Intn(len(commonDomains))]
			if rand.Intn(3) == 0 {
				prefixes := []string{"www", "api", "mail", "vpn", "dev"}
				domain = prefixes[rand.Intn(len(prefixes))] + "." + domain
			}
			srcPort := randomPort()
			query := buildDNSQueryType(domain, 0x0001)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 17, buildUDPDatagram(srcPort, 53, query))))
			resp := make([]byte, len(query))
			copy(resp, query)
			resp[2] = 0x81
			resp[3] = 0x80
			binary.BigEndian.PutUint16(resp[6:8], 0x0001)
			answer := []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 10, 0, byte(rand.Intn(5) + 1), byte(rand.Intn(200) + 10)}
			resp = append(resp, answer...)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 17, buildUDPDatagram(53, srcPort, resp))))
		case 2:
			id := uint16(rand.Intn(65535))
			seq := uint16(rand.Intn(512) + 1)
			echoPayload := make([]byte, []int{8, 16, 32, 56}[rand.Intn(4)])
			echoReq := buildICMPSegment(8, 0, 0, id, seq, echoPayload)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 1, echoReq)))
			if rand.Intn(5) != 0 {
				echoReply := buildICMPSegment(0, 0, 0, id, seq, echoPayload)
				frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 1, echoReply)))
			}
		case 3:
			srcPort := randomPort()
			clientSeq := rand.Uint32()
			serverSeq := rand.Uint32()
			paths := []string{"/", "/index.html", "/api/health", "/favicon.ico", "/robots.txt"}
			httpPort := []uint16{80, 8080, 8443}[rand.Intn(3)]
			syn := buildTCPSegment(srcPort, httpPort, 0x02, clientSeq, 0, nil)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 6, syn)))
			clientSeq++
			synAck := buildTCPSegment(httpPort, srcPort, 0x12, serverSeq, clientSeq, nil)
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 6, synAck)))
			serverSeq++
			getPayload := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", paths[rand.Intn(len(paths))], dst.IPAddress))
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 6, buildTCPSegment(srcPort, httpPort, 0x18, clientSeq, serverSeq, getPayload))))
			clientSeq += uint32(len(getPayload))
			respBody := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 6, buildTCPSegment(httpPort, srcPort, 0x18, serverSeq, clientSeq, respBody))))
		case 4:
			srcPort := randomPort()
			dstPort := []uint16{80, 443, 22, 3389, 8080}[rand.Intn(5)]
			seq := rand.Uint32()
			ackVal := rand.Uint32()
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(src.IPAddress, dst.IPAddress, 6, buildTCPSegment(srcPort, dstPort, 0x10, seq-1, ackVal, nil))))
			if rand.Intn(3) != 0 {
				frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dst.IPAddress, src.IPAddress, 6, buildTCPSegment(dstPort, srcPort, 0x10, ackVal, seq, nil))))
			}
		}
	}
	return frames
}

// PCAPHTTP2Reset generates a realistic HTTP/2 Rapid Reset attack PCAP
// (CVE-2023-44487): TLS handshake on port 443, HTTP/2 connection preface,
// SETTINGS exchange, then rapid HEADERS+RST_STREAM pairs representing the
// attack — each stream is opened and immediately reset before the server
// can respond, exhausting worker threads.
func PCAPHTTP2Reset(runID, attackerIP, targetIP string, streamCount int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPHTTP2Reset attacker=%s target=%s streams=%d", attackerIP, targetIP, streamCount)

	srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	srcPort := randomPort()
	clientSeq, serverSeq := rand.Uint32(), rand.Uint32()
	var frames [][]byte

	// TCP handshake
	syn := buildTCPSegment(srcPort, 443, 0x02, clientSeq, 0, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
	clientSeq++
	synAck := buildTCPSegment(443, srcPort, 0x12, serverSeq, clientSeq, nil)
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
	serverSeq++
	ack := buildTCPSegment(srcPort, 443, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ack)))

	// TLS handshake
	clientHello := buildTLSClientHelloSNI(targetIP)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 443, 0x18, clientSeq, serverSeq, clientHello))))
	clientSeq += uint32(len(clientHello))
	serverHello := buildMinimalTLSServerHello()
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(443, srcPort, 0x18, serverSeq, clientSeq, serverHello))))
	serverSeq += uint32(len(serverHello))
	tlsAck := buildTCPSegment(srcPort, 443, 0x10, clientSeq, serverSeq, nil)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, tlsAck)))

	// HTTP/2 connection preface (client)
	// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" followed by SETTINGS frame
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	// SETTINGS frame: length=0, type=0x4, flags=0x0, stream_id=0
	settingsFrame := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	clientPrefacePayload := append(preface, settingsFrame...)
	prefaceData := buildTLSApplicationData(clientPrefacePayload)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 443, 0x18, clientSeq, serverSeq, prefaceData))))
	clientSeq += uint32(len(prefaceData))

	// Server SETTINGS + SETTINGS ACK
	serverSettings := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}    // SETTINGS
	serverSettingsAck := []byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00} // SETTINGS ACK
	serverSettingsPayload := buildTLSApplicationData(append(serverSettings, serverSettingsAck...))
	frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, buildTCPSegment(443, srcPort, 0x18, serverSeq, clientSeq, serverSettingsPayload))))
	serverSeq += uint32(len(serverSettingsPayload))

	// Client SETTINGS ACK
	clientSettingsAck := []byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00}
	clientSettingsAckData := buildTLSApplicationData(clientSettingsAck)
	frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 443, 0x18, clientSeq, serverSeq, clientSettingsAckData))))
	clientSeq += uint32(len(clientSettingsAckData))

	// Cap stream count for PCAP size
	if streamCount > 100 {
		streamCount = 100
	}

	// Rapid HEADERS + RST_STREAM pairs — the actual attack
	// Each iteration opens a new stream (odd stream IDs: 1, 3, 5, ...)
	// and immediately resets it with RST_STREAM before server responds
	for i := 0; i < streamCount; i++ {
		streamID := uint32(i*2 + 1) // HTTP/2 client streams are odd-numbered

		// HEADERS frame: length=varies, type=0x1, flags=0x4 (END_HEADERS), stream_id
		headersPayload := []byte(fmt.Sprintf(":method: GET\r\n:path: /\r\n:scheme: https\r\n:authority: %s\r\n", targetIP))
		headersFrame := make([]byte, 9+len(headersPayload))
		headersFrame[0] = byte(len(headersPayload) >> 16)
		headersFrame[1] = byte(len(headersPayload) >> 8)
		headersFrame[2] = byte(len(headersPayload))
		headersFrame[3] = 0x01 // type HEADERS
		headersFrame[4] = 0x04 // END_HEADERS flag
		binary.BigEndian.PutUint32(headersFrame[5:9], streamID)
		copy(headersFrame[9:], headersPayload)
		headersData := buildTLSApplicationData(headersFrame)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 443, 0x18, clientSeq, serverSeq, headersData))))
		clientSeq += uint32(len(headersData))

		// RST_STREAM frame: length=4, type=0x3, flags=0x0, stream_id, error_code=0x8 (CANCEL)
		rstFrame := make([]byte, 13)
		rstFrame[0] = 0x00
		rstFrame[1] = 0x00
		rstFrame[2] = 0x04 // length=4
		rstFrame[3] = 0x03 // type RST_STREAM
		rstFrame[4] = 0x00 // flags=0
		binary.BigEndian.PutUint32(rstFrame[5:9], streamID)
		binary.BigEndian.PutUint32(rstFrame[9:13], 0x08) // CANCEL error code
		rstData := buildTLSApplicationData(rstFrame)
		frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, buildTCPSegment(srcPort, 443, 0x18, clientSeq, serverSeq, rstData))))
		clientSeq += uint32(len(rstData))
	}

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "http2_reset", finalFrames, defaultDuration)
	logInfo("Return from PCAPHTTP2Reset frames=%d path=%s", len(finalFrames), path)
	return path, err
}

// PCAPRUDYAttack generates a R.U.D.Y. (R-U-Dead-Yet) slow POST attack.
// Key distinction from regular HTTP: all connections are opened simultaneously,
// all send POST headers with Content-Length: 1000000, then drip one byte at a
// time ROUND-ROBIN across all connections. In Wireshark this shows as many
// parallel streams (stream 0,1,2,3,4) all frozen mid-body simultaneously —
// unmistakably different from normal HTTP which completes one request at a time.
// No connection ever sends a FIN.
func PCAPRUDYAttack(runID, attackerIP, targetIP string, connections, dripsPerConn int) (string, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering PCAPRUDYAttack attacker=%s target=%s conns=%d drips=%d", attackerIP, targetIP, connections, dripsPerConn)

	dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}

	type connState struct {
		srcMAC  [6]byte
		srcPort uint16
		seq     uint32
		ack     uint32
		srvSeq  uint32
	}
	states := make([]connState, connections)
	for c := 0; c < connections; c++ {
		states[c] = connState{
			srcMAC:  [6]byte{0x00, 0x11, 0x22, 0x33, byte(c >> 8), byte(c)},
			srcPort: uint16(49152 + c),
			seq:     rand.Uint32(),
			srvSeq:  rand.Uint32(),
		}
	}

	var frames [][]byte

	// --- Phase 1: Handshake ALL connections simultaneously ---
	// Wireshark shows streams 0,1,2,3,4 all opening at the same time.
	for c := 0; c < connections; c++ {
		s := &states[c]
		syn := buildTCPSegment(s.srcPort, 80, 0x02, s.seq, 0, nil)
		frames = append(frames, buildEthernetFrame(s.srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, syn)))
		s.seq++

		synAck := buildTCPSegment(80, s.srcPort, 0x12, s.srvSeq, s.seq, nil)
		frames = append(frames, buildEthernetFrame(dstMAC, s.srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, synAck)))
		s.srvSeq++
		s.ack = s.srvSeq

		ackSeg := buildTCPSegment(s.srcPort, 80, 0x10, s.seq, s.ack, nil)
		frames = append(frames, buildEthernetFrame(s.srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, ackSeg)))
	}

	// --- Phase 2: Send POST headers on ALL connections simultaneously ---
	// Every connection declares Content-Length: 1000000 — server threads all
	// block waiting for bodies that will never fully arrive.
	for c := 0; c < connections; c++ {
		s := &states[c]
		headers := []byte(fmt.Sprintf(
			"POST /login HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000000\r\nConnection: keep-alive\r\n\r\n",
			targetIP,
		))
		headerPush := buildTCPSegment(s.srcPort, 80, 0x18, s.seq, s.ack, headers)
		frames = append(frames, buildEthernetFrame(s.srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, headerPush)))
		s.seq += uint32(len(headers))

		srvAck := buildTCPSegment(80, s.srcPort, 0x10, s.srvSeq, s.seq, nil)
		frames = append(frames, buildEthernetFrame(dstMAC, s.srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, srvAck)))
	}

	// --- Phase 3: Drip one byte ROUND-ROBIN across all connections ---
	// This is what makes RUDY unmistakable: stream 0 sends 'A', then stream 1
	// sends 'A', then stream 2... then back to stream 0 sending 'B', etc.
	// Every stream is permanently mid-body. No stream ever finishes.
	for d := 0; d < dripsPerConn; d++ {
		for c := 0; c < connections; c++ {
			s := &states[c]
			drip := buildTCPSegment(s.srcPort, 80, 0x18, s.seq, s.ack, []byte{byte('A' + d%26)})
			frames = append(frames, buildEthernetFrame(s.srcMAC, dstMAC, buildIPv4Packet(attackerIP, targetIP, 6, drip)))
			s.seq++

			srvDripAck := buildTCPSegment(80, s.srcPort, 0x10, s.srvSeq, s.seq, nil)
			frames = append(frames, buildEthernetFrame(dstMAC, s.srcMAC, buildIPv4Packet(targetIP, attackerIP, 6, srvDripAck)))
		}
	}
	// No FIN on any connection — all server threads permanently blocked

	bgFrames := generateBackgroundTrafficN(getAllDevices(), connections*dripsPerConn/5)
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, err := writePCAPFile(runID, "rudy_attack", finalFrames, defaultDuration)
	logInfo("Return from PCAPRUDYAttack frames=%d path=%s", len(finalFrames), path)
	return path, err
}
