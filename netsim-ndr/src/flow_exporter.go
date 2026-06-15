// Package main — flow_exporter.go
// NetFlow v9, IPFIX (v10), and sFlow v5 binary packet generation and UDP export
// to the NDR sensor listening on the configured ports.
package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// FlowRecord represents a single network flow tuple.
type FlowRecord struct {
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    uint8     `json:"protocol"` // 6=TCP, 17=UDP, 1=ICMP
	Bytes       uint32    `json:"bytes"`
	Packets     uint32    `json:"packets"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	TCPFlags    uint8     `json:"tcp_flags"`
	InputIface  uint16    `json:"input_iface"`
	OutputIface uint16    `json:"output_iface"`
}

// GlobalNetflowConn is the UDP connection for NetFlow v9 export.
var GlobalNetflowConn net.Conn

// GlobalIPFIXConn is the UDP connection for IPFIX export.
var GlobalIPFIXConn net.Conn

// GlobalSflowConn is the UDP connection for sFlow export.
var GlobalSflowConn net.Conn

// GlobalFlowSeqNumber tracks the NetFlow/IPFIX sequence number.
var GlobalFlowSeqNumber uint32

// initFlowExporters opens UDP connections for all flow protocols.
func initFlowExporters() error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering initFlowExporters")

	ndrHost := configString("ndr.netflow.host", "127.0.0.1")
	netflowPort := configInt("ndr.netflow.port", 2055)
	ipfixPort := configInt("ndr.ipfix.port", 4739)
	sflowPort := configInt("ndr.sflow.port", 6343)

	var err error
	GlobalNetflowConn, err = net.Dial("udp", net.JoinHostPort(ndrHost, fmt.Sprintf("%d", netflowPort)))
	if err != nil {
		logWarn("initFlowExporters netflow dial: %v (continuing without NetFlow)", err)
	}
	GlobalIPFIXConn, err = net.Dial("udp", net.JoinHostPort(ndrHost, fmt.Sprintf("%d", ipfixPort)))
	if err != nil {
		logWarn("initFlowExporters ipfix dial: %v (continuing without IPFIX)", err)
	}
	GlobalSflowConn, err = net.Dial("udp", net.JoinHostPort(ndrHost, fmt.Sprintf("%d", sflowPort)))
	if err != nil {
		logWarn("initFlowExporters sflow dial: %v (continuing without sFlow)", err)
	}

	logInfo("Return from initFlowExporters")
	return nil
}

// netflowMaxRecordsPerPacket caps how many flow records go into a single
// NetFlow v9 datagram so the packet stays well under the UDP size limit.
const netflowMaxRecordsPerPacket = 30

// ExportNetflowV9 sends the given flow records to the NetFlow collector,
// splitting them across multiple datagrams so no single packet exceeds the
// maximum UDP payload size.
func ExportNetflowV9(exporterIP string, flows []FlowRecord) {
	defer panicHandler(traceFunc(), nil)
	if GlobalNetflowConn == nil {
		return
	}
	logInfo("Entering ExportNetflowV9 exporter=%s flows=%d", exporterIP, len(flows))

	totalBytes := 0
	for start := 0; start < len(flows); start += netflowMaxRecordsPerPacket {
		end := start + netflowMaxRecordsPerPacket
		if end > len(flows) {
			end = len(flows)
		}
		batch := flows[start:end]

		GlobalFlowSeqNumber++
		packet := buildNetflowV9Packet(exporterIP, batch, GlobalFlowSeqNumber)
		if _, err := GlobalNetflowConn.Write(packet); err != nil {
			logError("ExportNetflowV9 write: %v", err)
		} else {
			totalBytes += len(packet)
		}
	}

	for _, flow := range flows {
		storeFlowRecord(flow, exporterIP, "netflow9")
	}
	logInfo("Return from ExportNetflowV9 bytes=%d", totalBytes)
}

// buildNetflowV9Packet builds a binary NetFlow v9 packet.
// Format: Header (20 bytes) + Template FlowSet + Data FlowSet.
func buildNetflowV9Packet(exporterIP string, flows []FlowRecord, seqNum uint32) []byte {
	buf := make([]byte, 0, 512)

	// Template FlowSet
	templateSet := buildNetflowV9Template()

	// Data records
	dataRecords := make([]byte, 0, len(flows)*48)
	for _, flow := range flows {
		rec := buildNetflowV9DataRecord(flow)
		dataRecords = append(dataRecords, rec...)
	}

	// Data FlowSet header: FlowSet ID = Template ID (256), Length
	dataSetHdr := make([]byte, 4)
	binary.BigEndian.PutUint16(dataSetHdr[0:], 256)
	binary.BigEndian.PutUint16(dataSetHdr[2:], uint16(4+len(dataRecords)))
	dataSet := append(dataSetHdr, dataRecords...)

	// NetFlow v9 Header
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:], 9)                              // version
	binary.BigEndian.PutUint16(hdr[2:], uint16(2))                      // count (2 flowsets)
	binary.BigEndian.PutUint32(hdr[4:], uint32(time.Now().Unix()-3600)) // sys uptime ms (approximate)
	binary.BigEndian.PutUint32(hdr[8:], uint32(time.Now().Unix()))      // unix secs
	binary.BigEndian.PutUint32(hdr[12:], seqNum)                        // sequence
	binary.BigEndian.PutUint32(hdr[16:], ipToUint32(exporterIP))        // source ID

	buf = append(buf, hdr...)
	buf = append(buf, templateSet...)
	buf = append(buf, dataSet...)
	return buf
}

// buildNetflowV9Template builds a standard Template FlowSet for our flow record format.
func buildNetflowV9Template() []byte {
	fields := []struct{ id, length uint16 }{
		{8, 4},  // IPV4_SRC_ADDR
		{12, 4}, // IPV4_DST_ADDR
		{7, 2},  // L4_SRC_PORT
		{11, 2}, // L4_DST_PORT
		{4, 1},  // PROTOCOL
		{1, 4},  // IN_BYTES
		{2, 4},  // IN_PKTS
		{21, 4}, // LAST_SWITCHED (unix ms)
		{22, 4}, // FIRST_SWITCHED (unix ms)
		{6, 1},  // TCP_FLAGS
		{10, 2}, // INPUT_SNMP
		{14, 2}, // OUTPUT_SNMP
	}
	fieldCount := len(fields)
	recLen := 4 + fieldCount*4 // template header + fields
	buf := make([]byte, 4+4+recLen)
	binary.BigEndian.PutUint16(buf[0:], 0)                  // FlowSet ID = 0 (template)
	binary.BigEndian.PutUint16(buf[2:], uint16(4+recLen))   // Length
	binary.BigEndian.PutUint16(buf[4:], 256)                // Template ID
	binary.BigEndian.PutUint16(buf[6:], uint16(fieldCount)) // Field count
	offset := 8
	for _, field := range fields {
		binary.BigEndian.PutUint16(buf[offset:], field.id)
		binary.BigEndian.PutUint16(buf[offset+2:], field.length)
		offset += 4
	}
	return buf
}

// buildNetflowV9DataRecord encodes a single flow record into binary.
func buildNetflowV9DataRecord(flow FlowRecord) []byte {
	buf := make([]byte, 30)
	binary.BigEndian.PutUint32(buf[0:], ipToUint32(flow.SrcIP))
	binary.BigEndian.PutUint32(buf[4:], ipToUint32(flow.DstIP))
	binary.BigEndian.PutUint16(buf[8:], flow.SrcPort)
	binary.BigEndian.PutUint16(buf[10:], flow.DstPort)
	buf[12] = flow.Protocol
	binary.BigEndian.PutUint32(buf[13:], flow.Bytes)
	binary.BigEndian.PutUint32(buf[17:], flow.Packets)
	binary.BigEndian.PutUint32(buf[21:], uint32(flow.EndTime.Unix()))
	binary.BigEndian.PutUint32(buf[25:], uint32(flow.StartTime.Unix()))
	// tcp_flags, input_snmp, output_snmp are 1+2+2 = 5 bytes but we need len=30
	// Padding handled by 0-initialized slice
	return buf
}

// ExportIPFIX sends an IPFIX packet for the given flow records.
func ExportIPFIX(exporterIP string, flows []FlowRecord) {
	defer panicHandler(traceFunc(), nil)
	if GlobalIPFIXConn == nil {
		return
	}
	logInfo("Entering ExportIPFIX exporter=%s flows=%d", exporterIP, len(flows))

	GlobalFlowSeqNumber++
	packet := buildIPFIXPacket(flows, GlobalFlowSeqNumber)
	if _, err := GlobalIPFIXConn.Write(packet); err != nil {
		logError("ExportIPFIX write: %v", err)
	}
	for _, flow := range flows {
		storeFlowRecord(flow, exporterIP, "ipfix")
	}
	logInfo("Return from ExportIPFIX bytes=%d", len(packet))
}

// buildIPFIXPacket builds an IPFIX (v10) binary packet.
func buildIPFIXPacket(flows []FlowRecord, seqNum uint32) []byte {
	buf := make([]byte, 0, 512)

	// Encode data records
	dataRecords := make([]byte, 0, len(flows)*48)
	for _, flow := range flows {
		rec := buildNetflowV9DataRecord(flow) // same wire format
		dataRecords = append(dataRecords, rec...)
	}

	// Data Set: Set ID=256, Length
	dataSet := make([]byte, 4+len(dataRecords))
	binary.BigEndian.PutUint16(dataSet[0:], 256)
	binary.BigEndian.PutUint16(dataSet[2:], uint16(len(dataSet)))
	copy(dataSet[4:], dataRecords)

	totalLen := uint16(16 + len(dataSet))

	// IPFIX Message Header (16 bytes)
	hdr := make([]byte, 16)
	binary.BigEndian.PutUint16(hdr[0:], 10)                        // version = 10
	binary.BigEndian.PutUint16(hdr[2:], totalLen)                  // length
	binary.BigEndian.PutUint32(hdr[4:], uint32(time.Now().Unix())) // export time
	binary.BigEndian.PutUint32(hdr[8:], seqNum)                    // sequence number
	binary.BigEndian.PutUint32(hdr[12:], 1)                        // observation domain ID

	buf = append(buf, hdr...)
	buf = append(buf, dataSet...)
	return buf
}

// ExportSflow sends an sFlow v5 counter sample for a switch device.
func ExportSflow(switchDev *Device, flows []FlowRecord) {
	defer panicHandler(traceFunc(), nil)
	if GlobalSflowConn == nil {
		return
	}
	logInfo("Entering ExportSflow switch=%s flows=%d", switchDev.Name, len(flows))

	packet := buildSflowV5Packet(switchDev, flows)
	if _, err := GlobalSflowConn.Write(packet); err != nil {
		logError("ExportSflow write: %v", err)
	}
	for _, flow := range flows {
		storeFlowRecord(flow, switchDev.IPAddress, "sflow")
	}
	logInfo("Return from ExportSflow bytes=%d", len(packet))
}

// buildSflowV5Packet builds a minimal sFlow v5 datagram with flow samples.
func buildSflowV5Packet(switchDev *Device, flows []FlowRecord) []byte {
	buf := make([]byte, 0, 512)

	// sFlow v5 header (28 bytes)
	hdr := make([]byte, 28)
	binary.BigEndian.PutUint32(hdr[0:], 5)                               // version
	binary.BigEndian.PutUint32(hdr[4:], 1)                               // address type = IPv4
	binary.BigEndian.PutUint32(hdr[8:], ipToUint32(switchDev.IPAddress)) // agent address
	binary.BigEndian.PutUint32(hdr[12:], 1)                              // sub-agent ID
	binary.BigEndian.PutUint32(hdr[16:], GlobalFlowSeqNumber)            // sequence number
	binary.BigEndian.PutUint32(hdr[20:], 500)                            // uptime ms (fake)
	binary.BigEndian.PutUint32(hdr[24:], uint32(len(flows)))             // number of samples

	buf = append(buf, hdr...)

	for idx, flow := range flows {
		sample := buildSflowFlowSample(flow, uint32(idx))
		buf = append(buf, sample...)
	}
	return buf
}

// buildSflowFlowSample builds a single sFlow flow sample record.
func buildSflowFlowSample(flow FlowRecord, seqNum uint32) []byte {
	rawPkt := buildSflowRawPacketHeader(flow)
	// Flow sample header
	sampleLen := 44 + len(rawPkt)
	buf := make([]byte, 8+sampleLen)
	binary.BigEndian.PutUint32(buf[0:], 1) // enterprise=0, format=1 (flow sample)
	binary.BigEndian.PutUint32(buf[4:], uint32(sampleLen))
	binary.BigEndian.PutUint32(buf[8:], seqNum) // sequence
	binary.BigEndian.PutUint32(buf[12:], 1000)  // sampling rate
	binary.BigEndian.PutUint32(buf[16:], 1000)  // sample pool
	binary.BigEndian.PutUint32(buf[20:], 0)     // drops
	binary.BigEndian.PutUint32(buf[24:], 1)     // input
	binary.BigEndian.PutUint32(buf[28:], 2)     // output
	binary.BigEndian.PutUint32(buf[32:], 1)     // num records
	// Record type = raw packet header
	binary.BigEndian.PutUint32(buf[36:], 1) // enterprise=0, format=1
	binary.BigEndian.PutUint32(buf[40:], uint32(len(rawPkt)))
	copy(buf[44:], rawPkt)
	return buf
}

// buildSflowRawPacketHeader builds a synthetic Ethernet/IP/TCP header for sFlow.
func buildSflowRawPacketHeader(flow FlowRecord) []byte {
	buf := make([]byte, 54) // Ethernet(14) + IP(20) + TCP(20)

	// Ethernet header
	buf[12] = 0x08
	buf[13] = 0x00 // IPv4

	// IP header
	buf[14] = 0x45 // version=4, IHL=5
	buf[15] = 0x00
	binary.BigEndian.PutUint16(buf[16:], 40) // total length (IP+TCP, no data)
	buf[22] = 64                             // TTL
	buf[23] = flow.Protocol
	binary.BigEndian.PutUint32(buf[26:], ipToUint32(flow.SrcIP))
	binary.BigEndian.PutUint32(buf[30:], ipToUint32(flow.DstIP))

	// TCP/UDP header
	binary.BigEndian.PutUint16(buf[34:], flow.SrcPort)
	binary.BigEndian.PutUint16(buf[36:], flow.DstPort)

	return buf
}

// --- Flow generation helpers for attack scenarios ---

// FlowScan creates flow records representing a port scan.
func FlowScan(attackerIP, targetIP string, ports []uint16, duration uint64) []FlowRecord {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering FlowScan attacker=%s target=%s ports=%d", attackerIP, targetIP, len(ports))
	var flows []FlowRecord
	for _, port := range ports {
		if duration > 0 {
			sleepTime := time.Second / time.Duration(duration)
			time.Sleep(sleepTime) // simulate scan duration
		}
		flows = append(flows, FlowRecord{
			SrcIP:     attackerIP,
			DstIP:     targetIP,
			SrcPort:   randomPort(),
			DstPort:   port,
			Protocol:  6,
			Bytes:     60,
			Packets:   1,
			StartTime: time.Now(),
			EndTime:   time.Now().Add(time.Millisecond),
			TCPFlags:  0x02, // SYN
		})
	}
	logInfo("Return from FlowScan flows=%d", len(flows))
	return flows
}

// FlowBeaconing creates periodic C2 flow records.
func FlowBeaconing(srcIP, dstIP string, count int, interval time.Duration) []FlowRecord {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering FlowBeaconing src=%s dst=%s count=%d", srcIP, dstIP, count)
	var flows []FlowRecord
	start := time.Now()
	for idx := 0; idx < count; idx++ {
		ts := start.Add(time.Duration(idx) * interval)
		flows = append(flows, FlowRecord{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   randomPort(),
			DstPort:   443,
			Protocol:  6,
			Bytes:     uint32(200 + rand.Intn(800)),
			Packets:   uint32(2 + rand.Intn(5)),
			StartTime: ts,
			EndTime:   ts.Add(500 * time.Millisecond),
			TCPFlags:  0x18, // PSH+ACK
		})
	}
	logInfo("Return from FlowBeaconing flows=%d", len(flows))
	return flows
}

// FlowExfil creates large outbound transfer flow records.
func FlowExfil(srcIP, dstIP string, totalBytes uint32) []FlowRecord {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering FlowExfil src=%s dst=%s bytes=%d", srcIP, dstIP, totalBytes)
	flows := []FlowRecord{{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   randomPort(),
		DstPort:   443,
		Protocol:  6,
		Bytes:     totalBytes,
		Packets:   totalBytes / 1460,
		StartTime: time.Now().Add(-2 * time.Minute),
		EndTime:   time.Now(),
		TCPFlags:  0x18,
	}}
	logInfo("Return from FlowExfil flows=%d", len(flows))
	return flows
}

// FlowDDoS creates flood flows from multiple sources.
func FlowDDoS(sources []string, targetIP string, targetPort uint16, packetsPerSrc uint32) []FlowRecord {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering FlowDDoS sources=%d target=%s port=%d", len(sources), targetIP, targetPort)
	var flows []FlowRecord
	for _, src := range sources {
		flows = append(flows, FlowRecord{
			SrcIP:     src,
			DstIP:     targetIP,
			SrcPort:   randomPort(),
			DstPort:   targetPort,
			Protocol:  6,
			Bytes:     packetsPerSrc * 60,
			Packets:   packetsPerSrc,
			StartTime: time.Now().Add(-30 * time.Second),
			EndTime:   time.Now(),
			TCPFlags:  0x02,
		})
	}
	logInfo("Return from FlowDDoS flows=%d", len(flows))
	return flows
}

// FlowLateral creates internal SMB lateral movement flow records.
func FlowLateral(srcIP, dstIP string) []FlowRecord {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering FlowLateral src=%s dst=%s", srcIP, dstIP)
	flows := []FlowRecord{
		{SrcIP: srcIP, DstIP: dstIP, SrcPort: randomPort(), DstPort: 445, Protocol: 6, Bytes: 15000, Packets: 30, StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second), TCPFlags: 0x18},
		{SrcIP: srcIP, DstIP: dstIP, SrcPort: randomPort(), DstPort: 135, Protocol: 6, Bytes: 4000, Packets: 8, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second), TCPFlags: 0x18},
	}
	logInfo("Return from FlowLateral flows=%d", len(flows))
	return flows
}

// publishFlowsForDevice selects the correct protocol based on device telemetry and exports.
func publishFlowsForDevice(dev *Device, flows []FlowRecord) {
	defer panicHandler(traceFunc(), nil)
	if dev.Telemetry.Netflow {
		ExportNetflowV9(dev.IPAddress, flows)
	}
	if dev.Telemetry.Sflow {
		ExportSflow(dev, flows)
	}
}
