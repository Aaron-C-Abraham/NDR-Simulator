// Package main — attack_persistence.go
// Network-layer evasion attack implementations.
package main

import (
	"fmt"
	"math/rand"
	"time"
)

// ── Evasion ───────────────────────────────────────────────────────────────────

func runIPFragmentation(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runIPFragmentation attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fragSize := getAttackParamInt(req.Params, "frag_size", 8)
	if fragSize < 1 {
		return result, fmt.Errorf("frag_size must be at least 1, got %d", fragSize)
	}

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		devName := targetIP
		if targetDev != nil {
			devName = targetDev.Name
		}
		msgs := []string{
			fmt.Sprintf("IP fragmentation evasion: scan packets to %s fragmented to %d bytes — IDS reassembly evasion from %s", devName, fragSize, req.AttackerIP),
			fmt.Sprintf("Firewall: abnormal IP fragment stream from %s to %s — %d fragments per payload, possible IDS bypass", req.AttackerIP, devName, 1500/fragSize),
		}
		for _, msg := range msgs {
			fw := getFirewall()
			ev := sendSyslog(fw, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
	}

	fw := getFirewall()
	flows := []FlowRecord{}
	for _, targetIP := range req.TargetIPs {
		flows = append(flows, FlowRecord{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: uint16(randomPort()), DstPort: uint16(randomPort()), Protocol: 6, Bytes: 6000, Packets: uint32(1500 / fragSize), TCPFlags: 0x02, StartTime: time.Now().Add(-30 * time.Second), EndTime: time.Now()})
	}
	if len(req.TargetIPs) > 0 {
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, req.TargetIPs[0], "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
	}

	// PCAP — single file across all targets
	var fragPaths []string
	for _, targetIP := range req.TargetIPs {
		p, e := PCAPIPFragmentation(req.RunID, req.AttackerIP, targetIP, uint16(randomPort()), fragSize)
		if e == nil {
			fragPaths = append(fragPaths, p)
		}
	}
	if merged, merr := mergePCAPFiles(req.RunID, "ip_fragmentation", fragPaths); merr == nil {
		result.PCAPFiles = append(result.PCAPFiles, merged)
	}

	logInfo("Return from runIPFragmentation syslogs=%d", result.SyslogCount)
	return result, nil
}

func runProtocolTunnel(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runProtocolTunnel attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()

	for _, targetIP := range req.TargetIPs {
		msgs := []string{
			fmt.Sprintf("Protocol tunneling: IPv6-in-IPv4 encapsulation detected from %s to %s — protocol 41 used to bypass IPv4 filters", req.AttackerIP, targetIP),
			fmt.Sprintf("DPI: IPv6-in-IPv4 tunnel (proto=41) from %s — C2 traffic hidden inside encapsulated IPv6 packets", req.AttackerIP),
			fmt.Sprintf("Firewall: outbound protocol-41 traffic from %s to %s — IPv4 filter bypass via IPv6 encapsulation", targetIP, req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(fw, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "IPv6-in-IPv4", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{
			SrcIP: req.AttackerIP, DstIP: targetIP,
			SrcPort: 0, DstPort: 0,
			Protocol: 41, Bytes: 2097152, Packets: 4096,
			StartTime: time.Now().Add(-5 * time.Minute), EndTime: time.Now(),
		}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "IPv6-in-IPv4", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
	}

	// PCAP — single file across all targets
	var tunPaths []string
	for _, targetIP := range req.TargetIPs {
		p, e := PCAPIPv6InIPv4Tunnel(req.RunID, req.AttackerIP, targetIP)
		if e == nil {
			tunPaths = append(tunPaths, p)
		}
	}
	if merged, merr := mergePCAPFiles(req.RunID, "protocol_tunnel", tunPaths); merr == nil {
		result.PCAPFiles = append(result.PCAPFiles, merged)
	}

	logInfo("Return from runProtocolTunnel syslogs=%d", result.SyslogCount)
	return result, nil
}

func runLowSlowScan(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runLowSlowScan attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}

	delayMs := getAttackParamInt(req.Params, "delay_ms", 1000)
	portCount := getAttackParamInt(req.Params, "ports", 8)
	if delayMs < 1 {
		delayMs = 1
	}
	if portCount < 1 {
		portCount = 1
	}
	if portCount > 1000 {
		portCount = 1000
	}

	delayDuration := time.Duration(delayMs) * time.Millisecond
	scanInterval := fmt.Sprintf("%dms", delayMs)

	allPorts := []uint16{22, 80, 443, 3389, 8080, 3306, 5432, 1433, 21, 23, 25, 53,
		110, 139, 445, 993, 995, 1723, 3306, 5900, 8443, 8888, 9090, 9200}
	var ports []uint16
	for i := 0; i < portCount; i++ {
		ports = append(ports, allPorts[i%len(allPorts)])
	}

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		devName := targetIP
		if targetDev != nil {
			devName = targetDev.Name
		}
		msgs := []string{
			fmt.Sprintf("Low-and-slow scan: %s probing %s at rate 1 port per %s — below detection threshold", req.AttackerIP, devName, scanInterval),
			fmt.Sprintf("Behavioral: %s sent SYN packets to %s across %d ports — slow scan pattern", req.AttackerIP, devName, portCount),
		}
		for _, msg := range msgs {
			fw := getFirewall()
			ev := sendSyslog(fw, msg, 5)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
	}

	fw := getFirewall()
	flows := []FlowRecord{}
	for idx, port := range ports {
		offset := time.Duration(idx) * delayDuration
		for _, targetIP := range req.TargetIPs {
			flows = append(flows, FlowRecord{
				SrcIP: req.AttackerIP, DstIP: targetIP,
				SrcPort: uint16(randomPort()), DstPort: port,
				Protocol: 6, Bytes: 60, Packets: 1, TCPFlags: 0x02,
				StartTime: time.Now().Add(-time.Duration(portCount)*delayDuration + offset),
				EndTime:   time.Now().Add(-time.Duration(portCount)*delayDuration + offset + time.Second),
			})
		}
	}
	if len(req.TargetIPs) > 0 {
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, req.TargetIPs[0], "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
	}

	// PCAP — single file across all targets
	var lowSlowPaths []string
	for _, targetIP := range req.TargetIPs {
		p, e := PCAPLowSlowScan(req.RunID, req.AttackerIP, targetIP, ports, delayDuration)
		if e == nil {
			lowSlowPaths = append(lowSlowPaths, p)
		}
	}
	if merged, merr := mergePCAPFiles(req.RunID, "low_slow_scan", lowSlowPaths); merr == nil {
		result.PCAPFiles = append(result.PCAPFiles, merged)
	}

	logInfo("Return from runLowSlowScan syslogs=%d", result.SyslogCount)
	return result, nil
}

func runDecoyScan(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runDecoyScan attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	numDecoys := getAttackParamInt(req.Params, "num_decoys", 10)
	decoyIPs := make([]string, numDecoys)
	for idx := range decoyIPs {
		decoyIPs[idx] = fmt.Sprintf("10.%d.%d.%d", rand.Intn(256), rand.Intn(256), 1+rand.Intn(254))
	}

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		devName := targetIP
		if targetDev != nil {
			devName = targetDev.Name
		}
		msgs := []string{
			fmt.Sprintf("Decoy scan: %s scanning %s using %d spoofed source IPs — attacker hidden among decoys", req.AttackerIP, devName, numDecoys),
			fmt.Sprintf("IDS: port scan detected to %s from %d different source IPs simultaneously — nmap -D decoy scan pattern", devName, numDecoys+1),
		}
		for _, msg := range msgs {
			fw := getFirewall()
			ev := sendSyslog(fw, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
	}

	fw := getFirewall()
	flows := []FlowRecord{}
	allSources := append([]string{req.AttackerIP}, decoyIPs...)
	for _, srcIP := range allSources {
		for _, targetIP := range req.TargetIPs {
			flows = append(flows, FlowRecord{
				SrcIP: srcIP, DstIP: targetIP,
				SrcPort: uint16(randomPort()), DstPort: uint16(randomPort()),
				Protocol: 6, Bytes: 60, Packets: 1, TCPFlags: 0x02,
				StartTime: time.Now().Add(-10 * time.Second), EndTime: time.Now(),
			})
		}
	}
	if len(req.TargetIPs) > 0 {
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, req.TargetIPs[0], "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
	}

	// PCAP — single file across all targets
	var decoyPaths []string
	for _, targetIP := range req.TargetIPs {
		p, e := PCAPDecoyScan(req.RunID, req.AttackerIP, targetIP, decoyIPs)
		if e == nil {
			decoyPaths = append(decoyPaths, p)
		}
	}
	if merged, merr := mergePCAPFiles(req.RunID, "decoy_scan", decoyPaths); merr == nil {
		result.PCAPFiles = append(result.PCAPFiles, merged)
	}

	logInfo("Return from runDecoyScan syslogs=%d", result.SyslogCount)
	return result, nil
}
