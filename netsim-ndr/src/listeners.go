// Package main — listeners.go
// UDP telemetry receivers for Syslog, NetFlow v9, IPFIX (v10), and sFlow v5.
// Parses incoming packets from real or simulated network devices and stores
// them in SQLite for display in the telemetry viewer.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Template Cache (NetFlow v9 / IPFIX) ──────────────────────────────────────

// NF9Field is a single field type+length from a NetFlow/IPFIX template.
type NF9Field struct {
	TypeID uint16
	Length uint16
}

// NF9Template is a parsed NetFlow v9 / IPFIX template record.
type NF9Template struct {
	TemplateID uint16
	Fields     []NF9Field
	RecordLen  int
}

// GlobalNF9Templates caches templates per exporter.
// key: "exporterIP:sourceID" → templateID → template
var GlobalNF9Templates = map[string]map[uint16]*NF9Template{}
var GlobalNF9TemplatesLock sync.RWMutex

// Standard NetFlow / IPFIX field type IDs.
const (
	nfFieldInBytes      = 1
	nfFieldInPkts       = 2
	nfFieldProtocol     = 4
	nfFieldTCPFlags     = 6
	nfFieldSrcPort      = 7
	nfFieldSrcAddr      = 8
	nfFieldInputSnmp    = 10
	nfFieldDstPort      = 11
	nfFieldDstAddr      = 12
	nfFieldOutputSnmp   = 14
	nfFieldLastSwitched = 21
	nfFieldFirstSwitched = 22
	nfFieldOutBytes     = 23
	nfFieldOutPkts      = 24
)

// ─── Listener Initialisation ──────────────────────────────────────────────────

// initTelemetryListeners starts all UDP receiver goroutines.
func initTelemetryListeners() error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering initTelemetryListeners")

	if !configBool("listener.enabled", true) {
		logInfo("initTelemetryListeners: listeners disabled by config")
		return nil
	}

	syslogPort := configInt("listener.syslog.port", 10514)
	netflowPort := configInt("listener.netflow.port", 12055)
	ipfixPort := configInt("listener.ipfix.port", 14739)
	sflowPort := configInt("listener.sflow.port", 16343)

	go listenSyslog(syslogPort)
	go listenNetflowV9(netflowPort)
	go listenIPFIX(ipfixPort)
	go listenSflow(sflowPort)

	logInfo("Return from initTelemetryListeners syslog=%d netflow=%d ipfix=%d sflow=%d",
		syslogPort, netflowPort, ipfixPort, sflowPort)
	return nil
}

// configBool returns a boolean config property with a fallback default.
func configBool(key string, defaultVal bool) bool {
	if GlobalConfig == nil {
		return defaultVal
	}
	return GlobalConfig.GetBool(key, defaultVal)
}

// ─── Syslog Listener ──────────────────────────────────────────────────────────

// listenSyslog opens a UDP socket and processes incoming syslog datagrams.
func listenSyslog(port int) {
	defer panicHandler(traceFunc(), nil)
	addr := net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		logWarn("listenSyslog: cannot bind :%d: %v", port, err)
		return
	}
	defer conn.Close()
	logInfo("listenSyslog: listening on UDP :%d", port)

	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			logError("listenSyslog read: %v", err)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		go processSyslogDatagram(raw, remote.IP.String())
	}
}

// processSyslogDatagram parses one syslog datagram and stores it.
func processSyslogDatagram(raw []byte, remoteIP string) {
	defer panicHandler(traceFunc(), nil)
	event := parseSyslogDatagram(raw, remoteIP)
	if event == nil {
		return
	}
	storeSyslogMessage(event)
	broadcastEvent("syslog_received", map[string]interface{}{
		"device_ip":   event.DeviceIP,
		"device_name": event.DeviceName,
		"format":      event.Format,
		"severity":    event.Severity,
		"message":     event.Message,
	})
}

// parseSyslogDatagram decodes a raw syslog UDP payload into a SyslogEvent.
// Supports RFC 3164, RFC 5424, CEF, and LEEF formats.
func parseSyslogDatagram(raw []byte, remoteIP string) *SyslogEvent {
	msg := strings.TrimSpace(string(raw))
	if len(msg) == 0 {
		return nil
	}

	// Parse PRI header <N>
	severity := 6
	facility := 23
	if strings.HasPrefix(msg, "<") {
		if idx := strings.Index(msg, ">"); idx > 0 && idx <= 5 {
			pri, convErr := strconv.Atoi(msg[1:idx])
			if convErr == nil {
				facility = pri / 8
				severity = pri % 8
			}
			msg = strings.TrimSpace(msg[idx+1:])
		}
	}

	// Detect format
	format := "rfc3164"
	if strings.Contains(msg, "CEF:") {
		format = "cef"
	} else if strings.Contains(msg, "LEEF:") {
		format = "leef"
	} else if len(msg) > 2 && msg[0] == '1' && msg[1] == ' ' {
		format = "rfc5424"
	}

	// Try to extract hostname from RFC 3164/5424 header
	deviceName := remoteIP
	cleanMsg := msg
	if format == "rfc3164" {
		// <PRI>MMM DD HH:MM:SS HOSTNAME MSG
		parts := strings.Fields(msg)
		if len(parts) >= 4 {
			deviceName = parts[3]
			cleanMsg = strings.Join(parts[4:], " ")
		}
	} else if format == "rfc5424" {
		// 1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED MSG
		parts := strings.Fields(msg)
		if len(parts) >= 3 {
			deviceName = parts[2]
		}
		if len(parts) >= 7 {
			cleanMsg = strings.Join(parts[7:], " ")
		}
	}

	raw2 := string(raw)
	if len(raw2) > 4096 {
		raw2 = raw2[:4096]
	}
	return &SyslogEvent{
		DeviceIP:   remoteIP,
		DeviceName: deviceName,
		Facility:   facility,
		Severity:   severity,
		Timestamp:  time.Now(),
		Message:    cleanMsg,
		Format:     format,
		Raw:        raw2,
	}
}

// ─── NetFlow v9 Listener ──────────────────────────────────────────────────────

// listenNetflowV9 opens a UDP socket for NetFlow v9 collection.
func listenNetflowV9(port int) {
	defer panicHandler(traceFunc(), nil)
	addr := net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		logWarn("listenNetflowV9: cannot bind :%d: %v", port, err)
		return
	}
	defer conn.Close()
	logInfo("listenNetflowV9: listening on UDP :%d", port)

	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			logError("listenNetflowV9 read: %v", err)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		go processNetflowV9Packet(raw, remote.IP.String())
	}
}

// processNetflowV9Packet parses one NetFlow v9 UDP datagram and stores flows.
func processNetflowV9Packet(data []byte, exporterIP string) {
	defer panicHandler(traceFunc(), nil)
	if len(data) < 20 {
		return
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != 9 {
		logTrace("processNetflowV9Packet: skipping version=%d from %s", version, exporterIP)
		return
	}

	sourceID := binary.BigEndian.Uint32(data[16:20])
	cacheKey := fmt.Sprintf("%s:%d", exporterIP, sourceID)

	GlobalNF9TemplatesLock.Lock()
	if GlobalNF9Templates[cacheKey] == nil {
		GlobalNF9Templates[cacheKey] = map[uint16]*NF9Template{}
	}
	GlobalNF9TemplatesLock.Unlock()

	offset := 20
	var flows []FlowRecord

	for offset+4 <= len(data) {
		flowsetID := binary.BigEndian.Uint16(data[offset : offset+2])
		flowsetLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if flowsetLen < 4 || offset+flowsetLen > len(data) {
			break
		}
		flowsetData := data[offset+4 : offset+flowsetLen]

		switch {
		case flowsetID == 0: // Template FlowSet
			parseNF9Templates(flowsetData, cacheKey)
		case flowsetID >= 256: // Data FlowSet
			recs := parseNF9DataRecords(flowsetData, flowsetID, cacheKey, exporterIP)
			flows = append(flows, recs...)
		}
		offset += flowsetLen
	}

	for _, flow := range flows {
		storeFlowRecord(flow, exporterIP, "netflow9")
		broadcastEvent("flow_received", map[string]interface{}{
			"src_ip":      flow.SrcIP,
			"dst_ip":      flow.DstIP,
			"src_port":    flow.SrcPort,
			"dst_port":    flow.DstPort,
			"protocol":    flow.Protocol,
			"bytes":       flow.Bytes,
			"exporter_ip": exporterIP,
			"flow_type":   "netflow9",
		})
	}
	logTrace("processNetflowV9Packet: exporter=%s stored=%d flows", exporterIP, len(flows))
}

// parseNF9Templates processes a NetFlow v9 Template FlowSet.
func parseNF9Templates(data []byte, cacheKey string) {
	offset := 0
	for offset+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[offset : offset+2])
		fieldCount := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if templateID == 0 {
			break
		}

		var fields []NF9Field
		recordLen := 0
		for fIdx := 0; fIdx < fieldCount && offset+4 <= len(data); fIdx++ {
			fieldType := binary.BigEndian.Uint16(data[offset : offset+2])
			fieldLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			fields = append(fields, NF9Field{TypeID: fieldType, Length: fieldLen})
			recordLen += int(fieldLen)
			offset += 4
		}

		GlobalNF9TemplatesLock.Lock()
		GlobalNF9Templates[cacheKey][templateID] = &NF9Template{
			TemplateID: templateID,
			Fields:     fields,
			RecordLen:  recordLen,
		}
		GlobalNF9TemplatesLock.Unlock()
		logTrace("parseNF9Templates: cacheKey=%s templateID=%d fields=%d recordLen=%d",
			cacheKey, templateID, len(fields), recordLen)
	}
}

// parseNF9DataRecords extracts FlowRecords from a NetFlow v9 Data FlowSet.
func parseNF9DataRecords(data []byte, templateID uint16, cacheKey, exporterIP string) []FlowRecord {
	GlobalNF9TemplatesLock.RLock()
	tmpl := GlobalNF9Templates[cacheKey][templateID]
	GlobalNF9TemplatesLock.RUnlock()

	if tmpl == nil || tmpl.RecordLen == 0 {
		logTrace("parseNF9DataRecords: no template for cacheKey=%s templateID=%d", cacheKey, templateID)
		return nil
	}

	var flows []FlowRecord
	offset := 0
	now := time.Now()

	for offset+tmpl.RecordLen <= len(data) {
		flow := FlowRecord{StartTime: now, EndTime: now}
		fieldOffset := offset

		for _, field := range tmpl.Fields {
			end := fieldOffset + int(field.Length)
			if end > len(data) {
				break
			}
			fd := data[fieldOffset:end]
			switch field.TypeID {
			case nfFieldSrcAddr:
				if field.Length == 4 {
					flow.SrcIP = fmt.Sprintf("%d.%d.%d.%d", fd[0], fd[1], fd[2], fd[3])
				}
			case nfFieldDstAddr:
				if field.Length == 4 {
					flow.DstIP = fmt.Sprintf("%d.%d.%d.%d", fd[0], fd[1], fd[2], fd[3])
				}
			case nfFieldSrcPort:
				if field.Length == 2 {
					flow.SrcPort = binary.BigEndian.Uint16(fd)
				}
			case nfFieldDstPort:
				if field.Length == 2 {
					flow.DstPort = binary.BigEndian.Uint16(fd)
				}
			case nfFieldProtocol:
				if field.Length == 1 {
					flow.Protocol = fd[0]
				}
			case nfFieldInBytes:
				flow.Bytes = readUint32Variable(fd)
			case nfFieldInPkts:
				flow.Packets = readUint32Variable(fd)
			case nfFieldTCPFlags:
				if field.Length == 1 {
					flow.TCPFlags = fd[0]
				}
			case nfFieldFirstSwitched:
				if field.Length == 4 {
					flow.StartTime = time.Unix(int64(binary.BigEndian.Uint32(fd)), 0)
				}
			case nfFieldLastSwitched:
				if field.Length == 4 {
					flow.EndTime = time.Unix(int64(binary.BigEndian.Uint32(fd)), 0)
				}
			}
			fieldOffset = end
		}

		if flow.SrcIP != "" && flow.DstIP != "" {
			flows = append(flows, flow)
		}
		offset += tmpl.RecordLen
	}
	return flows
}

// readUint32Variable reads a 1/2/4-byte big-endian value as uint32.
func readUint32Variable(b []byte) uint32 {
	switch len(b) {
	case 1:
		return uint32(b[0])
	case 2:
		return uint32(binary.BigEndian.Uint16(b))
	case 4:
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

// ─── IPFIX (v10) Listener ─────────────────────────────────────────────────────

// listenIPFIX opens a UDP socket for IPFIX collection.
func listenIPFIX(port int) {
	defer panicHandler(traceFunc(), nil)
	addr := net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		logWarn("listenIPFIX: cannot bind :%d: %v", port, err)
		return
	}
	defer conn.Close()
	logInfo("listenIPFIX: listening on UDP :%d", port)

	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			logError("listenIPFIX read: %v", err)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		go processIPFIXPacket(raw, remote.IP.String())
	}
}

// processIPFIXPacket parses one IPFIX (v10) UDP message and stores flows.
// IPFIX shares template+data concepts with NetFlow v9 but has a different header
// and uses Set ID 2 for templates (vs FlowSet ID 0 in NFv9).
func processIPFIXPacket(data []byte, exporterIP string) {
	defer panicHandler(traceFunc(), nil)
	if len(data) < 16 {
		return
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != 10 {
		logTrace("processIPFIXPacket: skipping version=%d from %s", version, exporterIP)
		return
	}

	// IPFIX header: version(2) length(2) exportTime(4) seqNum(4) domainID(4)
	domainID := binary.BigEndian.Uint32(data[12:16])
	cacheKey := fmt.Sprintf("%s:%d", exporterIP, domainID)

	GlobalNF9TemplatesLock.Lock()
	if GlobalNF9Templates[cacheKey] == nil {
		GlobalNF9Templates[cacheKey] = map[uint16]*NF9Template{}
	}
	GlobalNF9TemplatesLock.Unlock()

	offset := 16
	var flows []FlowRecord

	for offset+4 <= len(data) {
		setID := binary.BigEndian.Uint16(data[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if setLen < 4 || offset+setLen > len(data) {
			break
		}
		setData := data[offset+4 : offset+setLen]

		switch {
		case setID == 2: // Template Set
			parseNF9Templates(setData, cacheKey) // same wire format as NFv9
		case setID >= 256: // Data Set
			recs := parseNF9DataRecords(setData, setID, cacheKey, exporterIP)
			flows = append(flows, recs...)
		}
		offset += setLen
	}

	for _, flow := range flows {
		storeFlowRecord(flow, exporterIP, "ipfix")
		broadcastEvent("flow_received", map[string]interface{}{
			"src_ip":    flow.SrcIP,
			"dst_ip":    flow.DstIP,
			"src_port":  flow.SrcPort,
			"dst_port":  flow.DstPort,
			"protocol":  flow.Protocol,
			"bytes":     flow.Bytes,
			"flow_type": "ipfix",
		})
	}
	logTrace("processIPFIXPacket: exporter=%s stored=%d flows", exporterIP, len(flows))
}

// ─── sFlow v5 Listener ────────────────────────────────────────────────────────

// listenSflow opens a UDP socket for sFlow v5 collection.
func listenSflow(port int) {
	defer panicHandler(traceFunc(), nil)
	addr := net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		logWarn("listenSflow: cannot bind :%d: %v", port, err)
		return
	}
	defer conn.Close()
	logInfo("listenSflow: listening on UDP :%d", port)

	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			logError("listenSflow read: %v", err)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		go processSflowPacket(raw, remote.IP.String())
	}
}

// processSflowPacket parses one sFlow v5 datagram and stores flow samples.
func processSflowPacket(data []byte, exporterIP string) {
	defer panicHandler(traceFunc(), nil)
	if len(data) < 28 {
		return
	}

	version := binary.BigEndian.Uint32(data[0:4])
	if version != 5 {
		logTrace("processSflowPacket: skipping version=%d from %s", version, exporterIP)
		return
	}

	// sFlow v5 header (28 bytes):
	// version(4) addrType(4) agentAddr(4) subAgentID(4) seqNum(4) uptime(4) numSamples(4)
	numSamples := int(binary.BigEndian.Uint32(data[24:28]))
	offset := 28
	var flows []FlowRecord

	for sampleIdx := 0; sampleIdx < numSamples && offset+8 <= len(data); sampleIdx++ {
		sampleType := binary.BigEndian.Uint32(data[offset : offset+4])
		sampleLen := int(binary.BigEndian.Uint32(data[offset+4 : offset+8]))
		offset += 8
		if sampleLen < 0 || offset+sampleLen > len(data) {
			break
		}
		sampleData := data[offset : offset+sampleLen]

		enterprise := sampleType >> 12
		format := sampleType & 0xFFF

		if enterprise == 0 && format == 1 { // Flow Sample
			flow := parseSflowFlowSample(sampleData, exporterIP)
			if flow != nil {
				flows = append(flows, *flow)
			}
		}
		offset += sampleLen
	}

	for _, flow := range flows {
		storeFlowRecord(flow, exporterIP, "sflow")
		broadcastEvent("flow_received", map[string]interface{}{
			"src_ip":    flow.SrcIP,
			"dst_ip":    flow.DstIP,
			"src_port":  flow.SrcPort,
			"dst_port":  flow.DstPort,
			"protocol":  flow.Protocol,
			"bytes":     flow.Bytes,
			"flow_type": "sflow",
		})
	}
	logTrace("processSflowPacket: exporter=%s stored=%d flows", exporterIP, len(flows))
}

// parseSflowFlowSample extracts a FlowRecord from a Flow Sample body.
// Format: seqNum(4) srcIDType(4) samplingRate(4) samplePool(4) drops(4)
//         input(4) output(4) numRecords(4) [records...]
func parseSflowFlowSample(data []byte, exporterIP string) *FlowRecord {
	if len(data) < 32 {
		return nil
	}
	numRecords := int(binary.BigEndian.Uint32(data[28:32]))
	offset := 32

	for recIdx := 0; recIdx < numRecords && offset+8 <= len(data); recIdx++ {
		recordType := binary.BigEndian.Uint32(data[offset : offset+4])
		recordLen := int(binary.BigEndian.Uint32(data[offset+4 : offset+8]))
		offset += 8
		if recordLen < 0 || offset+recordLen > len(data) {
			break
		}
		recData := data[offset : offset+recordLen]

		enterprise := recordType >> 12
		format := recordType & 0xFFF

		if enterprise == 0 && format == 1 { // Raw Packet Header
			flow := parseSflowRawPacket(recData, exporterIP)
			if flow != nil {
				return flow
			}
		}
		offset += recordLen
	}
	return nil
}

// parseSflowRawPacket extracts src/dst IPs and ports from a sFlow raw packet header record.
// Format: headerProtocol(4) frameLength(4) stripped(4) headerLength(4) header[...]
func parseSflowRawPacket(data []byte, exporterIP string) *FlowRecord {
	if len(data) < 16 {
		return nil
	}
	// headerProtocol: 1=ETHERNET-ISO88023
	headerLen := int(binary.BigEndian.Uint32(data[12:16]))
	if len(data) < 16+headerLen {
		return nil
	}
	pkt := data[16 : 16+headerLen]

	flow := &FlowRecord{StartTime: time.Now(), EndTime: time.Now()}

	// Parse Ethernet frame (14 bytes) + IP header (min 20 bytes)
	if len(pkt) < 34 {
		return nil
	}

	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != 0x0800 { // Only IPv4
		return nil
	}

	// IP header starts at byte 14
	ip := pkt[14:]
	if len(ip) < 20 {
		return nil
	}
	ihl := int(ip[0]&0x0F) * 4
	flow.Protocol = ip[9]
	flow.SrcIP = fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15])
	flow.DstIP = fmt.Sprintf("%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19])
	flow.Bytes = uint32(binary.BigEndian.Uint16(ip[2:4]))

	// TCP/UDP ports
	if len(ip) >= ihl+4 && (flow.Protocol == 6 || flow.Protocol == 17) {
		transport := ip[ihl:]
		flow.SrcPort = binary.BigEndian.Uint16(transport[0:2])
		flow.DstPort = binary.BigEndian.Uint16(transport[2:4])
		if flow.Protocol == 6 && len(transport) >= 14 {
			flow.TCPFlags = transport[13]
		}
	}

	return flow
}

// ─── Listener Status API ──────────────────────────────────────────────────────

// ListenerStatus describes one running listener.
type ListenerStatus struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Enabled  bool   `json:"enabled"`
}

// getListenerStatuses returns the configured listener ports.
func getListenerStatuses() []ListenerStatus {
	enabled := configBool("listener.enabled", true)
	return []ListenerStatus{
		{Protocol: "syslog",  Port: configInt("listener.syslog.port", 10514),  Enabled: enabled},
		{Protocol: "netflow", Port: configInt("listener.netflow.port", 12055), Enabled: enabled},
		{Protocol: "ipfix",   Port: configInt("listener.ipfix.port", 14739),   Enabled: enabled},
		{Protocol: "sflow",   Port: configInt("listener.sflow.port", 16343),   Enabled: enabled},
	}
}
