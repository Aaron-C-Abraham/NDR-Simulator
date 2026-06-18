// Package main — attack_ext.go
// Extended attack implementations: Spoofing, Injection, Authentication, C2, Lateral Movement, Wireless.
package main

import (
	"fmt"
	"math/rand"
	"time"
)

// ── Spoofing (extended) ───────────────────────────────────────────────────────

func runDHCPStarvation(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runDHCPStarvation attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, swDev := range getRouters() {
		msgs := []string{
			fmt.Sprintf("DHCP pool exhausted: 254/254 leases consumed — requests from %s using spoofed MACs", req.AttackerIP),
			fmt.Sprintf("DHCP: DISCOVER flood from %s — 500 unique MACs in 10 seconds, pool empty", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(swDev, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", swDev.Name, req.AttackerIP, "255.255.255.255", "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: "255.255.255.255", SrcPort: 68, DstPort: 67, Protocol: 17, Bytes: 150000, Packets: 500, StartTime: time.Now().Add(-30 * time.Second), EndTime: time.Now()}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, "255.255.255.255", "UDP", flows)
	result.EventIDs = append(result.EventIDs, flowID)

	dhcpPath, dhcpErr := PCAPDHCPStarvation(req.RunID, 30)
	if dhcpErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, dhcpPath)
	}

	logInfo("Return from runDHCPStarvation syslogs=%d", result.SyslogCount)
	return result, nil
}

func runRogueDHCP(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runRogueDHCP attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fakeGW := getAttackParam(req.Params, "gateway_spoof", "10.0.1.99")
	fw := getFirewall()
	for _, swDev := range getRouters() {
		msgs := []string{
			fmt.Sprintf("Rogue DHCP server detected: %s offering gateway=%s — DHCP snooping alert", req.AttackerIP, fakeGW),
			fmt.Sprintf("DHCP OFFER conflict: %s advertising default-router %s on untrusted port Gi0/5", req.AttackerIP, fakeGW),
		}
		for _, msg := range msgs {
			ev := sendSyslog(swDev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", swDev.Name, req.AttackerIP, "255.255.255.255", "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: "255.255.255.255", SrcPort: 67, DstPort: 68, Protocol: 17, Bytes: 3000, Packets: 10, StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second)}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "sw-core", req.AttackerIP, "255.255.255.255", "UDP", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	roguePath, rogueErr := PCAPRogueDHCP(req.RunID, req.AttackerIP, fakeGW)
	if rogueErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, roguePath)
	}
	logInfo("Return from runRogueDHCP syslogs=%d", result.SyslogCount)
	return result, nil
}

func runVLANHopping(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runVLANHopping attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetVLAN := getAttackParamInt(req.Params, "target_vlan", 200)
	for _, swDev := range getRouters() {
		msgs := []string{
			fmt.Sprintf("VLAN hopping: double-tagged 802.1Q frame from %s targeting VLAN %d — trunk port Gi0/1", req.AttackerIP, targetVLAN),
			fmt.Sprintf("Switch: VLAN %d traffic received from untrusted port — possible VLAN hopping attack", targetVLAN),
		}
		for _, msg := range msgs {
			ev := sendSyslog(swDev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", swDev.Name, req.AttackerIP, fmt.Sprintf("vlan%d", targetVLAN), "ETH", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
	}
	fw := getFirewall()
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: fmt.Sprintf("10.0.%d.1", targetVLAN/10), SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 5000, Packets: 10, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second)}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "sw-core", req.AttackerIP, fmt.Sprintf("vlan%d", targetVLAN), "ETH", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	vlanPath, vlanErr := PCAPVLANHopping(req.RunID, req.AttackerIP, fmt.Sprintf("10.0.%d.1", targetVLAN/10), 100, uint16(targetVLAN))
	if vlanErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, vlanPath)
	}
	logInfo("Return from runVLANHopping syslogs=%d", result.SyslogCount)
	return result, nil
}

func runBGPHijack(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runBGPHijack attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	prefix := getAttackParam(req.Params, "prefix", "10.0.0.0/24")
	fw := getFirewall()
	msgs := []string{
		fmt.Sprintf("BGP UPDATE from %s: announcing prefix %s with AS_PATH 65001 — more-specific hijack detected", req.AttackerIP, prefix),
		fmt.Sprintf("BGP: route %s now via AS65001 (%s) — possible BGP hijack, expected via AS65000", prefix, req.AttackerIP),
		fmt.Sprintf("BGP session %s: unexpected prefix %s received — RPKI validation INVALID", req.AttackerIP, prefix),
	}
	dev := fw
	if routers := getRouters(); len(routers) > 0 {
		dev = routers[0]
	}
	for _, msg := range msgs {
		ev := sendSyslog(dev, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", dev.Name, req.AttackerIP, "bgp-peer", "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: dev.IPAddress, SrcPort: randomPort(), DstPort: 179, Protocol: 6, Bytes: 2000, Packets: 10, StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second), TCPFlags: 0x18}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, dev.IPAddress, "TCP", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	bgpPath, bgpErr := PCAPBGPHijack(req.RunID, req.AttackerIP, dev.IPAddress, prefix, 65001)
	if bgpErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, bgpPath)
	}
	logInfo("Return from runBGPHijack syslogs=%d", result.SyslogCount)
	return result, nil
}

// ── Injection (extended) ─────────────────────────────────────────────────────

func runXXEInjection(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runXXEInjection attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	endpoint := getAttackParam(req.Params, "endpoint", "/api/upload")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("%s - - \"POST %s HTTP/1.1\" 200 — XXE payload <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", req.AttackerIP, endpoint),
			fmt.Sprintf("WAF alert: XML External Entity injection from %s — file:/// URI scheme detected in XML body", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 8000, Packets: 6, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		xxePayload := []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/xml\r\n\r\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", endpoint, targetIP))
		xxeResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		xxePath, xxeErr := PCAPGenericTCPExchange(req.RunID, "xxe_injection", req.AttackerIP, targetIP, 80, xxePayload, xxeResp)
		if xxeErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, xxePath)
		}
	}
	logInfo("Return from runXXEInjection syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSSTInjection(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSSTInjection attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	endpoint := getAttackParam(req.Params, "endpoint", "/search")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("%s - - \"GET %s?q={{7*7}} HTTP/1.1\" 200 — SSTI probe: response contained '49'", req.AttackerIP, endpoint),
			fmt.Sprintf("WAF: template injection detected from %s — Jinja2 expression in query parameter", req.AttackerIP),
			fmt.Sprintf("%s - - \"GET %s?q={{config.__class__.__mro__}} HTTP/1.1\" 500 — RCE attempt via SSTI", req.AttackerIP, endpoint),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 4000, Packets: 8, StartTime: time.Now(), EndTime: time.Now().Add(3 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		sstiPayload := []byte(fmt.Sprintf("GET %s?q={{7*7}} HTTP/1.1\r\nHost: %s\r\n\r\n", endpoint, targetIP))
		sstiResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n49")
		sstiPath, sstiErr := PCAPGenericTCPExchange(req.RunID, "ssti_injection", req.AttackerIP, targetIP, 80, sstiPayload, sstiResp)
		if sstiErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, sstiPath)
		}
	}
	logInfo("Return from runSSTInjection syslogs=%d", result.SyslogCount)
	return result, nil
}

func runLFIAttack(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runLFIAttack attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	endpoint := getAttackParam(req.Params, "endpoint", "/view?file=")
	fw := getFirewall()
	paths := []string{"../../../etc/passwd", "../../../etc/shadow", "../../../../Windows/System32/drivers/etc/hosts", "php://filter/read=convert.base64-encode/resource=index.php"}
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		for _, path := range paths {
			msg := fmt.Sprintf("%s - - \"GET %s%s HTTP/1.1\" 200 — path traversal detected", req.AttackerIP, endpoint, path)
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 6000, Packets: 12, StartTime: time.Now(), EndTime: time.Now().Add(4 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		lfiPayload := []byte(fmt.Sprintf("GET %s%s HTTP/1.1\r\nHost: %s\r\n\r\n", endpoint, paths[0], targetIP))
		lfiResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		lfiPath, lfiErr := PCAPGenericTCPExchange(req.RunID, "lfi_attack", req.AttackerIP, targetIP, 80, lfiPayload, lfiResp)
		if lfiErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, lfiPath)
		}
	}
	logInfo("Return from runLFIAttack syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSSRFAttack(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSSRFAttack attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetURL := getAttackParam(req.Params, "target_url", "http://169.254.169.254/latest/meta-data/")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("SSRF detected: %s caused server %s to request %s", req.AttackerIP, targetIP, targetURL),
			fmt.Sprintf("WAF: SSRF attempt blocked from %s — internal URL detected in user-supplied parameter", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 1000, Packets: 4, StartTime: time.Now(), EndTime: time.Now().Add(time.Second), TCPFlags: 0x18},
			{SrcIP: targetIP, DstIP: "169.254.169.254", SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 2000, Packets: 4, StartTime: time.Now(), EndTime: time.Now().Add(time.Second), TCPFlags: 0x18},
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		ssrfPayload := []byte(fmt.Sprintf("GET /fetch?url=%s HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL, targetIP))
		ssrfResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		ssrfPath, ssrfErr := PCAPGenericTCPExchange(req.RunID, "ssrf_attack", req.AttackerIP, targetIP, 80, ssrfPayload, ssrfResp)
		if ssrfErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, ssrfPath)
		}
	}
	logInfo("Return from runSSRFAttack syslogs=%d", result.SyslogCount)
	return result, nil
}

func runNoSQLInjection(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runNoSQLInjection attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	endpoint := getAttackParam(req.Params, "endpoint", "/api/users")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("%s - - \"POST %s HTTP/1.1\" 200 — NoSQL injection: {\"password\":{\"$ne\":\"\"}} bypassed auth", req.AttackerIP, endpoint),
			fmt.Sprintf("WAF: MongoDB operator injection from %s — $ne/$gt operators in JSON body detected", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 3000, Packets: 6, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		nosqlPayload := []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}", endpoint, targetIP))
		nosqlResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		nosqlPath, nosqlErr := PCAPGenericTCPExchange(req.RunID, "nosql_injection", req.AttackerIP, targetIP, 80, nosqlPayload, nosqlResp)
		if nosqlErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, nosqlPath)
		}
	}
	logInfo("Return from runNoSQLInjection syslogs=%d", result.SyslogCount)
	return result, nil
}

func runHeaderInjection(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runHeaderInjection attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	endpoint := getAttackParam(req.Params, "endpoint", "/")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("HTTP header injection from %s: GET %s with Host: evil.com\\r\\nX-Forwarded-For: 127.0.0.1", req.AttackerIP, endpoint),
			fmt.Sprintf("Cache poisoning attempt from %s: injected X-Forwarded-Host header to redirect cached response", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 2000, Packets: 4, StartTime: time.Now(), EndTime: time.Now().Add(time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		headerPayload := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: evil.com\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n", endpoint))
		headerResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		headerPath, headerErr := PCAPGenericTCPExchange(req.RunID, "header_injection", req.AttackerIP, targetIP, 80, headerPayload, headerResp)
		if headerErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, headerPath)
		}
	}
	logInfo("Return from runHeaderInjection syslogs=%d", result.SyslogCount)
	return result, nil
}

// ── Authentication (extended) ────────────────────────────────────────────────

func runBruteForceFTP(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runBruteForceFTP attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	users := []string{"admin", "ftp", "anonymous", "user", "ftpuser"}
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		for _, user := range users {
			msg := fmt.Sprintf("FTP: %s login failed for user '%s' from %s — 530 Login incorrect", targetIP, user, req.AttackerIP)
			ev := sendSyslog(dev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
			time.Sleep(15 * time.Millisecond)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 21, Protocol: 6, Bytes: 3000, Packets: uint32(len(users) * 4), StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 21, "ftp", len(users), users)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runBruteForceFTP syslogs=%d", result.SyslogCount)
	return result, nil
}

func runBruteForceTelnet(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runBruteForceTelnet attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		users := []string{"admin", "cisco", "enable", "root", "operator", "guest", "manager", "user"}
		for idx := 0; idx < 8; idx++ {
			msg := fmt.Sprintf("Telnet: authentication failure for '%s' from %s — attempt %d/8", users[idx], req.AttackerIP, idx+1)
			ev := sendSyslog(dev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
			time.Sleep(20 * time.Millisecond)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 23, Protocol: 6, Bytes: 4000, Packets: 32, StartTime: time.Now(), EndTime: time.Now().Add(8 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 23, "telnet", len(users), users)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runBruteForceTelnet syslogs=%d", result.SyslogCount)
	return result, nil
}

func runBruteForceSMTP(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runBruteForceSMTP attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := getAttackParamInt(req.Params, "target_port", 587)
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		users := []string{"admin@corp.local", "sales@corp.local", "support@corp.local", "info@corp.local", "noreply@corp.local",
			"john.doe@corp.local", "accounts@corp.local", "billing@corp.local", "hr@corp.local", "it@corp.local"}
		for idx := 0; idx < 10; idx++ {
			msg := fmt.Sprintf("SMTP AUTH failure from %s: 535 Authentication failed — invalid credentials (attempt %d)", req.AttackerIP, idx+1)
			ev := sendSyslog(dev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
			time.Sleep(15 * time.Millisecond)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: uint16(targetPort), Protocol: 6, Bytes: 5000, Packets: 40, StartTime: time.Now(), EndTime: time.Now().Add(10 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, uint16(targetPort), "smtp", 10, users)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runBruteForceSMTP syslogs=%d", result.SyslogCount)
	return result, nil
}

func runBruteForceSNMP(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runBruteForceSNMP attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	attackerDev, _ := getDeviceByIP(req.AttackerIP)
	communities := []string{"public", "private", "community", "admin", "manager", "cisco", "secret", "network", "snmpd", "router"}
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		for _, c := range communities {
			status := "rejected"
			if c == "public" {
				status = "accepted"
			}
			msg := fmt.Sprintf("SNMP: community '%s' attempted from %s to %s — %s", c, req.AttackerIP, targetIP, status)
			ev := sendSyslog(dev, msg, 5)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 161, Protocol: 17, Bytes: uint32(len(communities) * 100), Packets: uint32(len(communities)), StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second)}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		if attackerDev == nil || dev == nil {
			logWarn("runBruteForceSNMP target=%s: no device with MAC address available, skipping PCAP", targetIP)
			continue
		}

		// PCAP: one query/response pair per community string attempted —
		// each is its own UDP datagram (SNMP has no handshake/session to
		// reuse across attempts), with the accepted community ('public')
		// getting a real GetResponse and the rest getting an SNMP error
		// response, matching the accepted/rejected split in the syslog above.
		srcMAC := parseMACAddress(attackerDev.MACAddress)
		dstMAC := parseMACAddress(dev.MACAddress)
		var frames [][]byte
		for _, c := range communities {
			srcPort := randomPort()
			query := buildUDPDatagram(srcPort, 161, SNMPQuery(c))
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(req.AttackerIP, targetIP, 17, query)))

			var resp []byte
			if c == "public" {
				resp = buildUDPDatagram(161, srcPort, SNMPresponse(c))
			} else {
				resp = buildUDPDatagram(161, srcPort, SNMPresponse(c)) // same helper; real SNMP auth failures often just time out rather than reply, but a same-shape response keeps this consistent with existing SNMPenum precedent rather than inventing a new error PDU
			}
			frames = append(frames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, req.AttackerIP, 17, resp)))
		}
		path, _ := writePCAPFile(req.RunID, "bruteforce_snmp", frames, defaultDuration)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runBruteForceSNMP syslogs=%d", result.SyslogCount)
	return result, nil
}

func runBruteForceWinRM(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runBruteForceWinRM attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := getAttackParamInt(req.Params, "target_port", 5985)
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		users := []string{"admin", "administrator", "winrm", "user", "svc-admin", "backup", "deploy", "test"}
		for idx := 0; idx < 8; idx++ {
			msg := fmt.Sprintf("WinRM: authentication failed for %s from %s — HTTP 401 Unauthorized (attempt %d)", users[idx], req.AttackerIP, idx+1)
			ev := sendSyslog(dev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
			time.Sleep(20 * time.Millisecond)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: uint16(targetPort), Protocol: 6, Bytes: 6000, Packets: 40, StartTime: time.Now(), EndTime: time.Now().Add(8 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, uint16(targetPort), "winrm", len(users), users)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runBruteForceWinRM syslogs=%d", result.SyslogCount)
	return result, nil
}

func runBruteForceVNC(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runBruteForceVNC attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		for idx := 0; idx < 6; idx++ {
			msg := fmt.Sprintf("VNC: connection from %s to %s rejected — authentication failure (attempt %d) — too many tries, retry in 60s", req.AttackerIP, targetIP, idx+1)
			ev := sendSyslog(dev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
			time.Sleep(20 * time.Millisecond)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 5900, Protocol: 6, Bytes: 3000, Packets: 24, StartTime: time.Now(), EndTime: time.Now().Add(6 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 5900, "vnc", 6, nil)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runBruteForceVNC syslogs=%d", result.SyslogCount)
	return result, nil
}

func runPassTheTicket(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runPassTheTicket attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	user := getAttackParam(req.Params, "user", "admin@corp.local")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("Kerberos: TGS request from %s for user '%s' — ticket presented from unexpected IP (Pass-the-Ticket)", req.AttackerIP, user),
			fmt.Sprintf("EventID 4768: Kerberos TGT requested for '%s' from %s — anomalous source IP", user, req.AttackerIP),
			fmt.Sprintf("EventID 4769: Kerberos service ticket requested for cifs/%s by '%s' from non-enrolled host %s", targetIP, user, req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 88, Protocol: 17, Bytes: 2000, Packets: 6, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second)},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 445, Protocol: 6, Bytes: 8000, Packets: 20, StartTime: time.Now(), EndTime: time.Now().Add(3 * time.Second), TCPFlags: 0x18},
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		pttPath, pttErr := PCAPPassTheTicket(req.RunID, req.AttackerIP, targetIP, "CORP.LOCAL", user)
		if pttErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, pttPath)
		}
	}
	logInfo("Return from runPassTheTicket syslogs=%d", result.SyslogCount)
	return result, nil
}

func runASREPRoasting(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runASREPRoasting attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("Kerberos AS-REQ without pre-auth from %s — user svc-backup@corp.local has UF_DONT_REQUIRE_PREAUTH", req.AttackerIP),
			fmt.Sprintf("EventID 4768: Kerberos pre-authentication not required for account 'svc-jenkins' — AS-REP hash captured from %s", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 88, Protocol: 17, Bytes: 3000, Packets: 8, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second)}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		asrepPath, asrepErr := PCAPASREPRoasting(req.RunID, req.AttackerIP, targetIP, "CORP.LOCAL", "svc-jenkins@corp.local")
		if asrepErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, asrepPath)
		}
	}
	logInfo("Return from runASREPRoasting syslogs=%d", result.SyslogCount)
	return result, nil
}

// ── C2 (extended) ────────────────────────────────────────────────────────────

func runICMPTunnel(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runICMPTunnel attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	count := getAttackParamInt(req.Params, "count", 30)
	fw := getFirewall()
	c2IP := realC2IP()
	msgs := []string{
		fmt.Sprintf("ICMP tunnel detected: %s sending ICMP echo with anomalously large payload (1400 bytes) to %s", req.AttackerIP, c2IP),
		fmt.Sprintf("IDS: ICMP covert channel — %d echo requests with non-null payloads from %s to %s", count, req.AttackerIP, c2IP),
	}
	for _, msg := range msgs {
		ev := sendSyslog(fw, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, c2IP, "ICMP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: c2IP, SrcPort: 0, DstPort: 0, Protocol: 1, Bytes: uint32(count * 1400), Packets: uint32(count), StartTime: time.Now().Add(-time.Duration(count) * time.Second), EndTime: time.Now()}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, c2IP, "ICMP", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	icmpTunPath, icmpTunErr := PCAPICMPTunnel(req.RunID, req.AttackerIP, c2IP, count)
	if icmpTunErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, icmpTunPath)
	}
	logInfo("Return from runICMPTunnel syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSMBChannel(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSMBChannel attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	pipe := getAttackParam(req.Params, "pipe_name", "\\PIPE\\srvsvc")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("SMB named pipe C2: %s writing to %s on %s at irregular intervals", req.AttackerIP, pipe, targetIP),
			fmt.Sprintf("IDS: covert channel detected — SMB2 WRITE to named pipe %s with encrypted payload from %s", pipe, req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 445, Protocol: 6, Bytes: 50000, Packets: 100, StartTime: time.Now().Add(-300 * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runSMBChannel syslogs=%d", result.SyslogCount)
	return result, nil
}

func runWebSocketC2(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runWebSocketC2 attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	count := getAttackParamInt(req.Params, "count", 20)
	fw := getFirewall()
	c2IP := realC2IP()
	msgs := []string{
		fmt.Sprintf("WebSocket C2: %s upgraded connection to wss://%s:443 — persistent bidirectional channel", req.AttackerIP, c2IP),
		fmt.Sprintf("IDS: WebSocket C2 detected from %s — %d command frames over 300s, irregular timing pattern", req.AttackerIP, count),
	}
	for _, msg := range msgs {
		ev := sendSyslog(fw, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, c2IP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: c2IP, SrcPort: randomPort(), DstPort: 443, Protocol: 6, Bytes: uint32(count * 2000), Packets: uint32(count * 10), StartTime: time.Now().Add(-300 * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, c2IP, "TCP", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	logInfo("Return from runWebSocketC2 syslogs=%d", result.SyslogCount)
	return result, nil
}

func runDomainFronting(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runDomainFronting attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	frontDomain := getAttackParam(req.Params, "front_domain", "cdn.example.com")
	count := getAttackParamInt(req.Params, "count", 10)
	fw := getFirewall()
	msgs := []string{
		fmt.Sprintf("Domain fronting: %s connecting to %s (CDN) but Host header = evil-c2.com — traffic disguised", req.AttackerIP, frontDomain),
		fmt.Sprintf("IDS: domain fronting C2 detected — SNI=%s but HTTP Host header mismatch from %s", frontDomain, req.AttackerIP),
	}
	for _, msg := range msgs {
		ev := sendSyslog(fw, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, frontDomain, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: fmt.Sprintf("104.21.%d.%d", rand.Intn(255), rand.Intn(255)), SrcPort: randomPort(), DstPort: 443, Protocol: 6, Bytes: uint32(count * 3000), Packets: uint32(count * 5), StartTime: time.Now().Add(-time.Duration(count*30) * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, frontDomain, "TCP", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	logInfo("Return from runDomainFronting syslogs=%d", result.SyslogCount)
	return result, nil
}

func runReverseShell(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runReverseShell attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	port := getAttackParamInt(req.Params, "port", 4444)
	count := getAttackParamInt(req.Params, "count", 5)
	fw := getFirewall()
	c2IP := realC2IP()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("Reverse shell: outbound connection from %s to %s:%d — /bin/bash spawned over socket", targetIP, c2IP, port),
			fmt.Sprintf("IDS: reverse shell callback detected — %s connecting to unusual external port %d on %s", targetIP, port, c2IP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, targetIP, c2IP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		for idx := 0; idx < count; idx++ {
			flows := []FlowRecord{{SrcIP: targetIP, DstIP: c2IP, SrcPort: randomPort(), DstPort: uint16(port), Protocol: 6, Bytes: uint32(rand.Intn(10000) + 500), Packets: uint32(rand.Intn(100) + 10), StartTime: time.Now().Add(-time.Duration(idx*30) * time.Second), EndTime: time.Now().Add(-time.Duration(idx*30-29) * time.Second), TCPFlags: 0x18}}
			if fw != nil && fw.Telemetry.Netflow {
				ExportNetflowV9(fw.IPAddress, flows)
			}
			result.FlowCount++
			flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", targetIP, c2IP, "TCP", flows)
			result.EventIDs = append(result.EventIDs, flowID)
		}

		rsPayload := []byte("id\n")
		rsResp := []byte("uid=0(root) gid=0(root) groups=0(root)\n")
		rsPath, rsErr := PCAPGenericTCPExchange(req.RunID, "reverse_shell", targetIP, c2IP, uint16(port), rsPayload, rsResp)
		if rsErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, rsPath)
		}
	}
	logInfo("Return from runReverseShell syslogs=%d flows=%d", result.SyslogCount, result.FlowCount)
	return result, nil
}

func runPowerShellC2(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runPowerShellC2 attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	count := getAttackParamInt(req.Params, "count", 15)
	fw := getFirewall()
	c2IP := realC2IP()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("PowerShell: encoded command executed on %s — IEX([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(...)))", targetIP),
			fmt.Sprintf("EDR: PowerShell C2 beacon from %s to %s — base64 encoded HTTPS POST every 60s with %d%% jitter", targetIP, c2IP, 20),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, targetIP, c2IP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: targetIP, DstIP: c2IP, SrcPort: randomPort(), DstPort: 443, Protocol: 6, Bytes: uint32(count * 4000), Packets: uint32(count * 8), StartTime: time.Now().Add(-time.Duration(count) * time.Minute), EndTime: time.Now(), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", targetIP, c2IP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runPowerShellC2 syslogs=%d", result.SyslogCount)
	return result, nil
}

func runDNSExfil(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runDNSExfil attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	domain := getAttackParam(req.Params, "domain", "exfil.evil.example")
	dataKB := getAttackParamInt(req.Params, "data_kb", 50)
	dnsDev := getDNSServer()
	fw := getFirewall()
	dev := fw
	if dnsDev != nil {
		dev = dnsDev
	}
	chunkCount := dataKB * 5
	msgs := []string{
		fmt.Sprintf("DNS exfiltration: %s sending %d base32-encoded TXT queries to %s — data size ~%dKB", req.AttackerIP, chunkCount, domain, dataKB),
		fmt.Sprintf("IDS: DNS exfil detected — high-entropy subdomain queries to %s from %s exceeding 100 queries/min", domain, req.AttackerIP),
	}
	for _, msg := range msgs {
		ev := sendSyslog(dev, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "dns", req.AttackerIP, domain, "UDP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	dnsTarget := "8.8.8.8"
	if dnsDev != nil {
		dnsTarget = dnsDev.IPAddress
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: dnsTarget, SrcPort: randomPort(), DstPort: 53, Protocol: 17, Bytes: uint32(dataKB * 1200), Packets: uint32(chunkCount * 2), StartTime: time.Now().Add(-time.Duration(chunkCount/10) * time.Second), EndTime: time.Now()}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, dnsTarget, "UDP", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	dnsPath, dnsErr := PCAPDNSExfilMulti(req.RunID, req.AttackerIP, dnsTarget, domain, chunkCount)
	if dnsErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, dnsPath)
	}
	logInfo("Return from runDNSExfil syslogs=%d", result.SyslogCount)
	return result, nil
}

func runICMPExfil(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runICMPExfil attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	dataKB := getAttackParamInt(req.Params, "data_kb", 20)
	fw := getFirewall()
	c2IP := realC2IP()
	msgs := []string{
		fmt.Sprintf("ICMP exfiltration: %s sending %dKB encoded in ICMP echo payloads to %s", req.AttackerIP, dataKB, c2IP),
		fmt.Sprintf("IDS: abnormal ICMP payload size from %s — %d bytes/packet (normal=64) — data exfil via ICMP", req.AttackerIP, 1400),
	}
	for _, msg := range msgs {
		ev := sendSyslog(fw, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, c2IP, "ICMP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: c2IP, SrcPort: 0, DstPort: 0, Protocol: 1, Bytes: uint32(dataKB * 1024), Packets: uint32(dataKB * 1024 / 1400), StartTime: time.Now().Add(-time.Duration(dataKB*5) * time.Second), EndTime: time.Now()}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, c2IP, "ICMP", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	packetCount := dataKB * 1024 / 1400
	if packetCount < 1 {
		packetCount = 1
	}
	icmpExfPath, icmpExfErr := PCAPICMPExfil(req.RunID, req.AttackerIP, c2IP, packetCount)
	if icmpExfErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, icmpExfPath)
	}
	logInfo("Return from runICMPExfil syslogs=%d", result.SyslogCount)
	return result, nil
}

// ── Lateral Movement (extended) ──────────────────────────────────────────────

func runWMILateral(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runWMILateral attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("WMI remote exec: %s → %s — Win32_Process.Create called via DCOM port 135", req.AttackerIP, targetIP),
			fmt.Sprintf("EventID 4648: WMI explicit credential logon from %s to %s — cmd.exe spawned remotely", req.AttackerIP, targetIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		highPort := uint16(49152 + rand.Intn(10000))
		flows := []FlowRecord{
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 135, Protocol: 6, Bytes: 3000, Packets: 10, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second), TCPFlags: 0x18},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: highPort, Protocol: 6, Bytes: 20000, Packets: 40, StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second), TCPFlags: 0x18},
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		// PCAP (Option B)
		wmiPath, wmiErr := PCAPLateralWMI(req.RunID, req.AttackerIP, targetIP, highPort)
		if wmiErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, wmiPath)
		}
	}
	logInfo("Return from runWMILateral syslogs=%d", result.SyslogCount)
	return result, nil
}

func runDCOMLateral(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runDCOMLateral attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("DCOM lateral movement: %s instantiating MMC20.Application on %s — ShellExecute('cmd.exe')", req.AttackerIP, targetIP),
			fmt.Sprintf("EventID 4624: DCOM network logon from %s to %s — process spawned under SYSTEM", req.AttackerIP, targetIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 135, Protocol: 6, Bytes: 15000, Packets: 30, StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		dcomPath, dcomErr := PCAPLateralDCOM(req.RunID, req.AttackerIP, targetIP)
		if dcomErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, dcomPath)
		}
	}
	logInfo("Return from runDCOMLateral syslogs=%d", result.SyslogCount)
	return result, nil
}

func runRDPHijack(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runRDPHijack attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("RDP session hijack: tscon.exe used on %s from %s — session 2 (admin) taken without credentials", targetIP, req.AttackerIP),
			fmt.Sprintf("EventID 4778: RDP session reconnected on %s — session owner changed to attacker from %s", targetIP, req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 3389, Protocol: 6, Bytes: 500000, Packets: 1000, StartTime: time.Now().Add(-60 * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		rdpPath, rdpErr := PCAPLateralRDPHijack(req.RunID, req.AttackerIP, targetIP)
		if rdpErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, rdpPath)
		}
	}
	logInfo("Return from runRDPHijack syslogs=%d", result.SyslogCount)
	return result, nil
}

func runFTPExfil(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runFTPExfil attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	dataMB := getAttackParamInt(req.Params, "data_mb", 50)
	fw := getFirewall()
	c2IP := realC2IP()
	msgs := []string{
		fmt.Sprintf("FTP exfiltration: %s uploading %dMB to %s:21 — STOR sensitive_data.zip", req.AttackerIP, dataMB, c2IP),
		fmt.Sprintf("IDS: large outbound FTP transfer from %s to external %s — %dMB in single session", req.AttackerIP, c2IP, dataMB),
	}
	for _, msg := range msgs {
		ev := sendSyslog(fw, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, c2IP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	flows := []FlowRecord{
		{SrcIP: req.AttackerIP, DstIP: c2IP, SrcPort: randomPort(), DstPort: 21, Protocol: 6, Bytes: 2000, Packets: 20, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second), TCPFlags: 0x18},
		{SrcIP: req.AttackerIP, DstIP: c2IP, SrcPort: randomPort(), DstPort: 20, Protocol: 6, Bytes: uint32(dataMB * 1048576), Packets: uint32(dataMB * 700), StartTime: time.Now(), EndTime: time.Now().Add(time.Duration(dataMB) * time.Second), TCPFlags: 0x18},
	}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount += len(flows)
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, c2IP, "TCP", flows)
	result.EventIDs = append(result.EventIDs, flowID)

	ftpPayload := []byte("STOR sensitive_data.zip\r\n")
	ftpResp := []byte("150 Opening BINARY mode data connection.\r\n226 Transfer complete.\r\n")
	ftpPath, ftpErr := PCAPGenericTCPExchange(req.RunID, "ftp_exfil", req.AttackerIP, c2IP, 21, ftpPayload, ftpResp)
	if ftpErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, ftpPath)
	}

	logInfo("Return from runFTPExfil syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSMTPExfil(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSMTPExfil attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	dataMB := getAttackParamInt(req.Params, "data_mb", 10)
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("SMTP exfiltration from %s: email to attacker@evil.example with %dMB attachment via %s", req.AttackerIP, dataMB, targetIP),
			fmt.Sprintf("DLP alert: outbound email from %s with sensitive attachment (%dMB) to external domain evil.example", req.AttackerIP, dataMB),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 25, Protocol: 6, Bytes: uint32(dataMB * 1048576), Packets: uint32(dataMB * 700), StartTime: time.Now(), EndTime: time.Now().Add(time.Duration(dataMB*5) * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		smtpPayload := []byte(fmt.Sprintf("MAIL FROM:<%s>\r\nRCPT TO:<attacker@evil.example>\r\nDATA\r\n", req.AttackerIP))
		smtpResp := []byte("250 OK\r\n250 OK\r\n354 Start mail input; end with <CRLF>.<CRLF>\r\n")
		smtpPath, smtpErr := PCAPGenericTCPExchange(req.RunID, "smtp_exfil", req.AttackerIP, targetIP, 25, smtpPayload, smtpResp)
		if smtpErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, smtpPath)
		}
	}
	logInfo("Return from runSMTPExfil syslogs=%d", result.SyslogCount)
	return result, nil
}

func runGoldenTicket(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runGoldenTicket attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	user := getAttackParam(req.Params, "user", "administrator@corp.local")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("Golden Ticket: forged Kerberos TGT for '%s' from %s — ticket lifetime 10 years, no DC validation", user, req.AttackerIP),
			fmt.Sprintf("EventID 4769: service ticket request with anomalous TGT — encryption type DES (RC4) from %s for '%s'", req.AttackerIP, user),
			fmt.Sprintf("DC alert: TGT presented from %s with PAC inconsistency — possible Golden Ticket attack", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 88, Protocol: 17, Bytes: 5000, Packets: 12, StartTime: time.Now(), EndTime: time.Now().Add(3 * time.Second)},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 445, Protocol: 6, Bytes: 50000, Packets: 80, StartTime: time.Now(), EndTime: time.Now().Add(10 * time.Second), TCPFlags: 0x18},
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		goldenPath, goldenErr := PCAPGoldenTicket(req.RunID, req.AttackerIP, targetIP, "CORP.LOCAL", user)
		if goldenErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, goldenPath)
		}
	}
	logInfo("Return from runGoldenTicket syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSSHTunnel(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSSHTunnel attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	localPort := getAttackParamInt(req.Params, "local_port", 8080)
	remotePort := getAttackParamInt(req.Params, "remote_port", 3306)
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("SSH tunnel: %s forwarding local:%d → %s:%d (MySQL) — pivot through firewall", req.AttackerIP, localPort, targetIP, remotePort),
			fmt.Sprintf("IDS: SSH port forwarding detected from %s — traffic to internal port %d tunneled over port 22", req.AttackerIP, remotePort),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 22, Protocol: 6, Bytes: 500000, Packets: 1000, StartTime: time.Now().Add(-300 * time.Second), EndTime: time.Now(), TCPFlags: 0x18},
			{SrcIP: targetIP, DstIP: fmt.Sprintf("10.0.3.%d", 1+rand.Intn(50)), SrcPort: randomPort(), DstPort: uint16(remotePort), Protocol: 6, Bytes: 200000, Packets: 400, StartTime: time.Now().Add(-290 * time.Second), EndTime: time.Now(), TCPFlags: 0x18},
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		sshPayload := []byte("SSH-2.0-OpenSSH_8.9\r\n")
		sshResp := []byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
		sshPath, sshErr := PCAPGenericTCPExchange(req.RunID, "ssh_tunnel", req.AttackerIP, targetIP, 22, sshPayload, sshResp)
		if sshErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, sshPath)
		}
	}
	logInfo("Return from runSSHTunnel syslogs=%d", result.SyslogCount)
	return result, nil
}

// ── Wireless (extended) ──────────────────────────────────────────────────────

func runPMKIDAttack(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runPMKIDAttack attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	apName := getAttackParam(req.Params, "ap_name", "ap-floor1")
	dev := getFirewall()
	_ = apName
	if dev == nil {
		return result, nil
	}
	msgs := []string{
		fmt.Sprintf("PMKID attack: %s captured EAPOL frame from AP '%s' — WPA2 PMKID extracted for offline cracking", req.AttackerIP, apName),
		fmt.Sprintf("Wireless IDS: PMKID capture attempt from %s on AP %s — no client association required", req.AttackerIP, apName),
	}
	for _, msg := range msgs {
		ev := sendSyslog(dev, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", dev.Name, req.AttackerIP, dev.IPAddress, "802.11", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	logInfo("Return from runPMKIDAttack syslogs=%d", result.SyslogCount)
	return result, nil
}

func runEvilTwin(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runEvilTwin attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	ssid := getAttackParam(req.Params, "ssid", "Corp-WiFi")
	dev := getFirewall()
	if dev == nil {
		return result, nil
	}
	msgs := []string{
		fmt.Sprintf("Evil twin detected: rogue AP broadcasting SSID '%s' from %s with stronger signal (-55 dBm vs legitimate -70 dBm)", ssid, req.AttackerIP),
		fmt.Sprintf("Wireless IDS: unauthorized AP with SSID '%s' detected at MAC %s — captive portal active", ssid, req.AttackerIP),
		fmt.Sprintf("Client association alert: 3 clients switched from legitimate AP to rogue '%s' at %s", ssid, req.AttackerIP),
	}
	for _, msg := range msgs {
		ev := sendSyslog(dev, msg, 2)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", dev.Name, req.AttackerIP, dev.IPAddress, "802.11", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	logInfo("Return from runEvilTwin syslogs=%d", result.SyslogCount)
	return result, nil
}
