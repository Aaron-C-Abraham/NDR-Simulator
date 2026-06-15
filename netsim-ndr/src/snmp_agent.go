// Package main — snmp_agent.go
// Minimal SNMP v1/v2c agent that exposes all topology devices via standard
// MIB-II OIDs so that any NMS tool (PRTG, Zabbix, snmpwalk, LibreNMS, etc.)
// can discover and monitor the simulated network.
//
// Endpoints exposed:
//   GET /api/v1/snmp/status   — agent status + OID count + sample commands
//   POST /api/v1/snmp/rebuild — force OID tree rebuild from current topology
//
// UDP listener binds to snmp.port (default 161).
// On Windows port 161 is available without elevation; on Linux use 1161 or run as root.
//
// MIB layout (all devices share one agent at 127.0.0.1):
//   1.3.6.1.2.1.1.*          — System group (sysDescr, sysName, sysLocation …)
//   1.3.6.1.2.1.2.*          — Interfaces group (one entry per topology device)
//   1.3.6.1.2.1.4.20.*       — IP Address table (one entry per device IP)
//   1.3.6.1.4.1.99999.1.N.*  — Enterprise device table (name, type, zone, OS, vendor, status)
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── BER / SNMP type constants ─────────────────────────────────────────────────

const (
	berInteger   byte = 0x02
	berOctetStr  byte = 0x04
	berNull      byte = 0x05
	berObjID     byte = 0x06
	berSequence  byte = 0x30
	berIPAddress byte = 0x40
	berCounter32 byte = 0x41
	berGauge32   byte = 0x42
	berTimeTicks byte = 0x43
	berEndOfMIB  byte = 0x82

	pduGetRequest  byte = 0xA0
	pduGetNext     byte = 0xA1
	pduGetResponse byte = 0xA2
	pduGetBulk     byte = 0xA5

	snmpErrNoError    = 0
	snmpErrNoSuchName = 2
)

// ── OID value ─────────────────────────────────────────────────────────────────

type snmpValue struct {
	berType byte
	data    []byte
}

// ── SNMP agent ────────────────────────────────────────────────────────────────

type snmpAgent struct {
	mu        sync.RWMutex
	tree      map[string]snmpValue
	sorted    []string
	startTime time.Time
	community string
	port      string
	conn      *net.UDPConn
	running   bool
}

var GlobalSNMPAgent = &snmpAgent{}

// initSNMPAgent builds the OID tree from topology and starts the UDP listener.
func initSNMPAgent() {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering initSNMPAgent")

	GlobalSNMPAgent.startTime = time.Now()
	GlobalSNMPAgent.community = configString("snmp.community", "public")
	GlobalSNMPAgent.port = configString("snmp.port", "161")

	GlobalSNMPAgent.rebuildOIDTree()

	addr, err := net.ResolveUDPAddr("udp4", ":"+GlobalSNMPAgent.port)
	if err != nil {
		logError("initSNMPAgent resolve: %v", err)
		return
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		logError("initSNMPAgent listen udp:%s: %v — try snmp.port=1161 for non-root", GlobalSNMPAgent.port, err)
		return
	}
	GlobalSNMPAgent.conn = conn
	GlobalSNMPAgent.running = true
	go GlobalSNMPAgent.serve()
	logInfo("Return from initSNMPAgent port=%s community=%s oids=%d",
		GlobalSNMPAgent.port, GlobalSNMPAgent.community, len(GlobalSNMPAgent.sorted))
}

// rebuildOIDTree reads current topology from DB and rebuilds the full OID tree.
func (a *snmpAgent) rebuildOIDTree() {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering snmpAgent.rebuildOIDTree")

	devices := getAllDevices()
	tree := make(map[string]snmpValue, 256)

	// ─── System group 1.3.6.1.2.1.1 ─────────────────────────────────────────
	set := func(oid string, t byte, v []byte) { tree[oid] = snmpValue{t, v} }

	set("1.3.6.1.2.1.1.1.0", berOctetStr, []byte(fmt.Sprintf("NDR Test Environment Simulator — %d devices", len(devices))))
	set("1.3.6.1.2.1.1.2.0", berObjID, encodeOIDValue([]int{1, 3, 6, 1, 4, 1, 99999}))
	set("1.3.6.1.2.1.1.3.0", berTimeTicks, encodeUint32(0)) // overwritten live in serve()
	set("1.3.6.1.2.1.1.4.0", berOctetStr, []byte("ndr-simulator@algomox"))
	set("1.3.6.1.2.1.1.5.0", berOctetStr, []byte("netsim-ndr"))
	set("1.3.6.1.2.1.1.6.0", berOctetStr, []byte("Virtual Security Lab"))
	set("1.3.6.1.2.1.1.7.0", berInteger, encodeInt32(72))

	// ─── Interfaces group 1.3.6.1.2.1.2 ─────────────────────────────────────
	set("1.3.6.1.2.1.2.1.0", berInteger, encodeInt32(int32(len(devices))))

	ifTypeFor := map[string]int32{
		"router": 131, "firewall": 131, "switch": 6,
		"server": 6, "workstation": 6, "wireless_ap": 71, "iot": 6,
	}
	ifSpeedFor := map[string]uint32{
		"router": 4294967295, "firewall": 4294967295, "switch": 4294967295,
		"server": 1000000000, "workstation": 1000000000,
		"wireless_ap": 300000000, "iot": 100000000,
	}

	for i, dev := range devices {
		n := int32(i + 1)
		ifsuf := fmt.Sprintf(".%d", n)
		base := "1.3.6.1.2.1.2.2.1."

		set(base+"1"+ifsuf, berInteger, encodeInt32(n))
		set(base+"2"+ifsuf, berOctetStr, []byte(dev.Name+" ("+dev.DeviceType+")"))

		ifType, ok := ifTypeFor[dev.DeviceType]
		if !ok {
			ifType = 6
		}
		set(base+"3"+ifsuf, berInteger, encodeInt32(ifType))

		ifSpeed, ok := ifSpeedFor[dev.DeviceType]
		if !ok {
			ifSpeed = 1000000000
		}
		set(base+"5"+ifsuf, berGauge32, encodeUint32(ifSpeed))
		set(base+"6"+ifsuf, berOctetStr, parseMACBytes(dev.MACAddress))
		set(base+"7"+ifsuf, berInteger, encodeInt32(1)) // ifAdminStatus up
		set(base+"8"+ifsuf, berInteger, encodeInt32(1)) // ifOperStatus up
		set(base+"10"+ifsuf, berCounter32, encodeUint32(0))
		set(base+"16"+ifsuf, berCounter32, encodeUint32(0))
		set(base+"20"+ifsuf, berCounter32, encodeUint32(0))
		set(base+"21"+ifsuf, berCounter32, encodeUint32(0))

		// ─── IP Address table 1.3.6.1.2.1.4.20.1 ────────────────────────────
		if dev.IPAddress != "" {
			ipSuf := "." + dev.IPAddress
			ipBase := "1.3.6.1.2.1.4.20.1."
			set(ipBase+"1"+ipSuf, berIPAddress, parseIPv4Bytes(dev.IPAddress))
			set(ipBase+"2"+ipSuf, berInteger, encodeInt32(n))
			set(ipBase+"3"+ipSuf, berIPAddress, parseIPv4Bytes("255.255.255.0"))
			set(ipBase+"4"+ipSuf, berInteger, encodeInt32(1))
			set(ipBase+"5"+ipSuf, berInteger, encodeInt32(16)) // prefix length
		}

		// ─── Enterprise device table 1.3.6.1.4.1.99999.1.N ──────────────────
		devBase := fmt.Sprintf("1.3.6.1.4.1.99999.1.%d.", n)
		set(devBase+"1", berOctetStr, []byte(dev.ID))
		set(devBase+"2", berOctetStr, []byte(dev.Name))
		set(devBase+"3", berOctetStr, []byte(dev.DeviceType))
		set(devBase+"4", berOctetStr, []byte(dev.NetworkZone))
		set(devBase+"5", berOctetStr, []byte(dev.IPAddress))
		set(devBase+"6", berOctetStr, []byte(dev.MACAddress))
		set(devBase+"7", berOctetStr, []byte(dev.OSType))
		set(devBase+"8", berOctetStr, []byte(dev.Vendor))
		statusVal := int32(1) // up
		if dev.Status != "active" {
			statusVal = 2
		}
		set(devBase+"9", berInteger, encodeInt32(statusVal))
	}

	// Sort OID keys for GETNEXT
	sorted := make([]string, 0, len(tree))
	for k := range tree {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return oidStringLess(sorted[i], sorted[j])
	})

	a.mu.Lock()
	a.tree = tree
	a.sorted = sorted
	a.mu.Unlock()
	logInfo("Return from snmpAgent.rebuildOIDTree devices=%d oids=%d", len(devices), len(tree))
}

// serve reads UDP packets and dispatches each to a goroutine.
func (a *snmpAgent) serve() {
	defer panicHandler(traceFunc(), nil)
	logInfo("snmpAgent.serve listening on udp:%s", a.port)
	buf := make([]byte, 65535)
	for {
		n, remote, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			if a.running {
				logError("snmpAgent.serve ReadFromUDP: %v", err)
			}
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go a.handlePacket(pkt, remote)
	}
}

// handlePacket decodes an SNMP request and writes a GET-RESPONSE.
func (a *snmpAgent) handlePacket(raw []byte, remote *net.UDPAddr) {
	defer panicHandler(traceFunc(), nil)

	msg, err := decodeSNMPMessage(raw)
	if err != nil {
		logTrace("snmpAgent.handlePacket decode error from %s: %v", remote, err)
		return
	}
	if msg.community != a.community {
		logTrace("snmpAgent.handlePacket wrong community %q from %s", msg.community, remote)
		return
	}

	upticks := uint32(time.Since(a.startTime).Seconds() * 100)

	a.mu.RLock()
	defer a.mu.RUnlock()

	var vbs []snmpVarbind
	errStatus := snmpErrNoError
	errIndex := 0

	switch msg.pduType {
	case pduGetRequest:
		for i, vb := range msg.varbinds {
			if vb.oid == "1.3.6.1.2.1.1.3.0" {
				vbs = append(vbs, snmpVarbind{vb.oid, berTimeTicks, encodeUint32(upticks)})
				continue
			}
			val, ok := a.tree[vb.oid]
			if !ok {
				errStatus = snmpErrNoSuchName
				errIndex = i + 1
				vbs = append(vbs, snmpVarbind{vb.oid, berNull, nil})
			} else {
				vbs = append(vbs, snmpVarbind{vb.oid, val.berType, val.data})
			}
		}

	case pduGetNext, pduGetBulk:
		for _, vb := range msg.varbinds {
			next, found := a.nextOID(vb.oid)
			if !found {
				vbs = append(vbs, snmpVarbind{vb.oid, berEndOfMIB, nil})
				continue
			}
			if next == "1.3.6.1.2.1.1.3.0" {
				vbs = append(vbs, snmpVarbind{next, berTimeTicks, encodeUint32(upticks)})
			} else {
				val := a.tree[next]
				vbs = append(vbs, snmpVarbind{next, val.berType, val.data})
			}
		}

	default:
		return
	}

	resp := encodeSNMPResponse(msg.version, msg.community, msg.requestID, errStatus, errIndex, vbs)
	if _, err := a.conn.WriteToUDP(resp, remote); err != nil {
		logTrace("snmpAgent.handlePacket write: %v", err)
	}
}

// nextOID returns the lexicographically next OID after the given one.
func (a *snmpAgent) nextOID(oid string) (string, bool) {
	for _, k := range a.sorted {
		if oidStringLess(oid, k) {
			return k, true
		}
	}
	return "", false
}

// SNMPAgentStatus is returned by the status API.
type SNMPAgentStatus struct {
	Running   bool   `json:"running"`
	Port      string `json:"port"`
	Community string `json:"community"`
	OIDCount  int    `json:"oid_count"`
	DeviceCount int  `json:"device_count"`
	UptimeSec int64  `json:"uptime_sec"`
	Commands  []string `json:"sample_commands"`
}

// getSNMPAgentStatus returns the current agent status.
func getSNMPAgentStatus() SNMPAgentStatus {
	GlobalSNMPAgent.mu.RLock()
	oidCount := len(GlobalSNMPAgent.sorted)
	GlobalSNMPAgent.mu.RUnlock()

	port := GlobalSNMPAgent.port
	community := GlobalSNMPAgent.community
	devCount := len(getAllDevices())

	host := "127.0.0.1"
	portStr := ""
	if port != "161" {
		portStr = ":" + port
	}

	return SNMPAgentStatus{
		Running:     GlobalSNMPAgent.running,
		Port:        port,
		Community:   community,
		OIDCount:    oidCount,
		DeviceCount: devCount,
		UptimeSec:   int64(time.Since(GlobalSNMPAgent.startTime).Seconds()),
		Commands: []string{
			fmt.Sprintf("snmpwalk -v2c -c %s %s%s", community, host, portStr),
			fmt.Sprintf("snmpwalk -v2c -c %s %s%s 1.3.6.1.2.1.2.2", community, host, portStr),
			fmt.Sprintf("snmpwalk -v2c -c %s %s%s 1.3.6.1.2.1.4.20", community, host, portStr),
			fmt.Sprintf("snmpwalk -v2c -c %s %s%s 1.3.6.1.4.1.99999", community, host, portStr),
		},
	}
}

// ── SNMP message types ────────────────────────────────────────────────────────

type snmpMessage struct {
	version   int
	community string
	pduType   byte
	requestID int32
	varbinds  []snmpVarbind
}

type snmpVarbind struct {
	oid     string
	berType byte
	data    []byte
}

// ── SNMP packet decoder ───────────────────────────────────────────────────────

func decodeSNMPMessage(pkt []byte) (*snmpMessage, error) {
	typ, content, _, err := berRead(pkt)
	if err != nil || typ != berSequence {
		return nil, fmt.Errorf("outer sequence: %v", err)
	}
	// version
	typ, val, rest, err := berRead(content)
	if err != nil || typ != berInteger {
		return nil, fmt.Errorf("version: %v", err)
	}
	version := int(berDecodeInt(val))
	content = rest
	// community
	typ, val, rest, err = berRead(content)
	if err != nil || typ != berOctetStr {
		return nil, fmt.Errorf("community: %v", err)
	}
	community := string(val)
	content = rest
	// PDU
	pduType, pduContent, _, err := berRead(content)
	if err != nil {
		return nil, fmt.Errorf("pdu: %v", err)
	}
	// request-id
	_, val, rest, err = berRead(pduContent)
	if err != nil {
		return nil, fmt.Errorf("request-id: %v", err)
	}
	reqID := berDecodeInt(val)
	pduContent = rest
	// error-status (skip)
	_, _, rest, err = berRead(pduContent)
	if err != nil {
		return nil, fmt.Errorf("err-status: %v", err)
	}
	pduContent = rest
	// error-index (skip)
	_, _, rest, err = berRead(pduContent)
	if err != nil {
		return nil, fmt.Errorf("err-index: %v", err)
	}
	pduContent = rest
	// varbind-list
	_, vblContent, _, err := berRead(pduContent)
	if err != nil {
		return nil, fmt.Errorf("vblist: %v", err)
	}
	var vbs []snmpVarbind
	for len(vblContent) > 0 {
		var vbContent []byte
		_, vbContent, vblContent, err = berRead(vblContent)
		if err != nil {
			break
		}
		typ, oidBytes, _, err := berRead(vbContent)
		if err != nil || typ != berObjID {
			break
		}
		vbs = append(vbs, snmpVarbind{oid: berDecodeOID(oidBytes)})
	}
	return &snmpMessage{
		version:   version,
		community: community,
		pduType:   pduType,
		requestID: reqID,
		varbinds:  vbs,
	}, nil
}

// ── SNMP response encoder ─────────────────────────────────────────────────────

func encodeSNMPResponse(version int, community string, reqID int32, errStatus, errIndex int, vbs []snmpVarbind) []byte {
	var vbList []byte
	for _, vb := range vbs {
		oidTLV := berTLV(berObjID, encodeOIDValue(parseOIDString(vb.oid)))
		var valTLV []byte
		switch vb.berType {
		case berNull, 0:
			valTLV = berTLV(berNull, nil)
		case berEndOfMIB:
			valTLV = berTLV(berEndOfMIB, nil)
		default:
			valTLV = berTLV(vb.berType, vb.data)
		}
		vbList = append(vbList, berTLV(berSequence, append(oidTLV, valTLV...))...)
	}
	pdu := berTLV(pduGetResponse, concat(
		berTLV(berInteger, encodeInt32(reqID)),
		berTLV(berInteger, encodeInt32(int32(errStatus))),
		berTLV(berInteger, encodeInt32(int32(errIndex))),
		berTLV(berSequence, vbList),
	))
	msg := concat(
		berTLV(berInteger, encodeInt32(int32(version))),
		berTLV(berOctetStr, []byte(community)),
		pdu,
	)
	return berTLV(berSequence, msg)
}

// ── BER primitives ────────────────────────────────────────────────────────────

// berRead returns (type, value-bytes, remaining-bytes, error).
func berRead(data []byte) (byte, []byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("too short (%d)", len(data))
	}
	typ := data[0]
	length, used, err := berReadLength(data[1:])
	if err != nil {
		return 0, nil, nil, err
	}
	start := 1 + used
	end := start + length
	if end > len(data) {
		return 0, nil, nil, fmt.Errorf("truncated: need %d have %d", end, len(data))
	}
	return typ, data[start:end], data[end:], nil
}

func berReadLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty length field")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	n := int(data[0] & 0x7F)
	if n == 0 || n > 4 || len(data) < n+1 {
		return 0, 0, fmt.Errorf("invalid long-form length")
	}
	length := 0
	for i := 1; i <= n; i++ {
		length = length<<8 | int(data[i])
	}
	return length, n + 1, nil
}

func berWriteLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n <= 0xFF {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n & 0xFF)}
}

func berTLV(typ byte, val []byte) []byte {
	out := []byte{typ}
	out = append(out, berWriteLength(len(val))...)
	return append(out, val...)
}

// ── Integer helpers ───────────────────────────────────────────────────────────

func encodeInt32(v int32) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	i := 0
	if v > 0 {
		for i < 3 && b[i] == 0x00 && b[i+1]&0x80 == 0 {
			i++
		}
	} else {
		for i < 3 && b[i] == 0xFF && b[i+1]&0x80 != 0 {
			i++
		}
	}
	return b[i:]
}

func encodeUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func berDecodeInt(b []byte) int32 {
	if len(b) == 0 {
		return 0
	}
	var result int32
	if b[0]&0x80 != 0 {
		result = -1
	}
	for _, octet := range b {
		result = result<<8 | int32(octet)
	}
	return result
}

// ── OID helpers ───────────────────────────────────────────────────────────────

// encodeOIDValue encodes an integer slice to BER OID bytes.
func encodeOIDValue(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}
	out := []byte{byte(oid[0]*40 + oid[1])}
	for _, sub := range oid[2:] {
		if sub == 0 {
			out = append(out, 0x00)
			continue
		}
		var enc []byte
		for sub > 0 {
			enc = append([]byte{byte(sub & 0x7F)}, enc...)
			sub >>= 7
		}
		for i, b := range enc {
			if i < len(enc)-1 {
				out = append(out, b|0x80)
			} else {
				out = append(out, b)
			}
		}
	}
	return out
}

// berDecodeOID decodes BER OID bytes to dotted string.
func berDecodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	first := int(b[0])
	parts := []string{fmt.Sprintf("%d", first/40), fmt.Sprintf("%d", first%40)}
	i := 1
	for i < len(b) {
		val := 0
		for i < len(b) {
			octet := int(b[i])
			i++
			val = val<<7 | (octet & 0x7F)
			if octet&0x80 == 0 {
				break
			}
		}
		parts = append(parts, fmt.Sprintf("%d", val))
	}
	return strings.Join(parts, ".")
}

// parseOIDString parses "1.3.6.1.2.1.1.1.0" → []int.
func parseOIDString(s string) []int {
	parts := strings.Split(s, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		var n int
		fmt.Sscan(p, &n)
		result = append(result, n)
	}
	return result
}

// oidStringLess compares two dotted OID strings numerically.
func oidStringLess(a, b string) bool {
	ap := parseOIDString(a)
	bp := parseOIDString(b)
	for i := 0; i < len(ap) && i < len(bp); i++ {
		if ap[i] != bp[i] {
			return ap[i] < bp[i]
		}
	}
	return len(ap) < len(bp)
}

// ── IP / MAC helpers ──────────────────────────────────────────────────────────

func parseIPv4Bytes(ip string) []byte {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return []byte{0, 0, 0, 0}
	}
	b := make([]byte, 4)
	for i, p := range parts {
		var n int
		fmt.Sscan(p, &n)
		b[i] = byte(n)
	}
	return b
}

func parseMACBytes(mac string) []byte {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return make([]byte, 6)
	}
	b := make([]byte, 6)
	for i, p := range parts {
		var n int
		fmt.Sscanf(p, "%x", &n)
		b[i] = byte(n)
	}
	return b
}

// concat joins byte slices.
func concat(slices ...[]byte) []byte {
	var out []byte
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}
