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
		fragSize = 1
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
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount += len(flows)
	if len(req.TargetIPs) > 0 {
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, req.TargetIPs[0], "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runIPFragmentation syslogs=%d", result.SyslogCount)
	return result, nil
}

func runProtocolTunnel(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runProtocolTunnel attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	tunnelProto := getAttackParam(req.Params, "tunnel_protocol", "DNS")
	c2IP := realC2IP()
	fw := getFirewall()
	msgs := []string{
		fmt.Sprintf("Protocol tunneling: C2 traffic encapsulated in %s from %s to %s — anomalous payload size", tunnelProto, req.AttackerIP, c2IP),
		fmt.Sprintf("DPI: %s traffic shows non-standard payload entropy 7.8 bits/byte from %s — possible tunnel", tunnelProto, req.AttackerIP),
		fmt.Sprintf("Firewall: allowed %s sessions carrying unexpected binary content from %s to external %s", tunnelProto, req.AttackerIP, c2IP),
	}
	for _, msg := range msgs {
		ev := sendSyslog(fw, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, c2IP, tunnelProto, ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	var proto uint8 = 17
	dstPort := uint16(53)
	if tunnelProto == "ICMP" {
		proto = 1
		dstPort = 0
	} else if tunnelProto == "HTTP" {
		proto = 6
		dstPort = 80
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: c2IP, SrcPort: uint16(randomPort()), DstPort: dstPort, Protocol: proto, Bytes: 2097152, Packets: 4096, StartTime: time.Now().Add(-5 * time.Minute), EndTime: time.Now()}}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, c2IP, tunnelProto, flows)
	result.EventIDs = append(result.EventIDs, flowID)
	logInfo("Return from runProtocolTunnel syslogs=%d", result.SyslogCount)
	return result, nil
}

func runLowSlowScan(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runLowSlowScan attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	scanInterval := getAttackParam(req.Params, "scan_interval", "30s")
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		devName := targetIP
		if targetDev != nil {
			devName = targetDev.Name
		}
		msgs := []string{
			fmt.Sprintf("Low-and-slow scan: %s probing %s at rate 1 port per %s — below detection threshold", req.AttackerIP, devName, scanInterval),
			fmt.Sprintf("Behavioral: %s sent SYN packets to %s across 120 ports over 1 hour — slow scan pattern", req.AttackerIP, devName),
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
	ports := []uint16{22, 80, 443, 3389, 8080, 3306, 5432, 1433}
	for idx, port := range ports {
		offset := time.Duration(idx*30) * time.Second
		for _, targetIP := range req.TargetIPs {
			flows = append(flows, FlowRecord{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: uint16(randomPort()), DstPort: port, Protocol: 6, Bytes: 60, Packets: 1, TCPFlags: 0x02, StartTime: time.Now().Add(-time.Hour + offset), EndTime: time.Now().Add(-time.Hour + offset + time.Second)})
		}
	}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount += len(flows)
	if len(req.TargetIPs) > 0 {
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, req.TargetIPs[0], "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
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
			flows = append(flows, FlowRecord{SrcIP: srcIP, DstIP: targetIP, SrcPort: uint16(randomPort()), DstPort: uint16(randomPort()), Protocol: 6, Bytes: 60, Packets: 1, TCPFlags: 0x02, StartTime: time.Now().Add(-10 * time.Second), EndTime: time.Now()})
		}
	}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount += len(flows)
	if len(req.TargetIPs) > 0 {
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, req.TargetIPs[0], "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runDecoyScan syslogs=%d", result.SyslogCount)
	return result, nil
}
