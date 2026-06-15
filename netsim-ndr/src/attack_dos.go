// Package main — attack_dos.go
// DoS / DDoS attack module implementations.
package main

import (
	"fmt"
	"math/rand"
	"time"
)

// runSYNFlood generates TCP SYN flood telemetry.
func runSYNFlood(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSYNFlood attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := uint16(getAttackParamInt(req.Params, "target_port", 443))
	pps := getAttackParamInt(req.Params, "pps", 10000)
	duration := getAttackParamInt(req.Params, "duration", 30)
	fw := getFirewall()

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)

		// Build spoofed source IPs (SYN flood uses spoofed sources)
		var sources []string
		for idx := 0; idx < 50; idx++ {
			sources = append(sources, fmt.Sprintf("203.0.%d.%d", rand.Intn(255), 1+rand.Intn(254)))
		}

		// Syslog on firewall: SYN flood detected
		msgs := []string{
			fmt.Sprintf("DOS detected: SYN flood from multiple sources to %s:%d — %d pps over %ds", targetIP, targetPort, pps, duration),
			fmt.Sprintf("IDS alert: DDOS SYN flood targeting %s port %d", targetIP, targetPort),
			fmt.Sprintf("Connection table exhausted: %s:%d — dropping new connections", targetIP, targetPort),
		}
		for _, msg := range msgs {
			ev := sendSyslog(fw, msg, 1)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		// Syslog on target: high CPU / connection table full
		if targetDev != nil && targetDev.Telemetry.Syslog {
			devMsg := fmt.Sprintf("kernel: SYNFLOOD: possible SYN flooding on port %d. Sending cookies.", targetPort)
			ev := sendSyslog(targetDev, devMsg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		// Flows: flood from many sources
		flows := FlowDDoS(sources[:10], targetIP, targetPort, uint32(pps*duration/10))
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPSYNFlood(req.RunID, targetIP, targetPort, sources)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealSYNProbes(targetIP, int(targetPort), 50)
	}

	logInfo("Return from runSYNFlood syslogs=%d flows=%d pcap=%d", result.SyslogCount, result.FlowCount, len(result.PCAPFiles))
	return result, nil
}

// runUDPFlood generates UDP flood telemetry.
func runUDPFlood(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runUDPFlood attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := uint16(getAttackParamInt(req.Params, "target_port", 53))
	pps := getAttackParamInt(req.Params, "pps", 50000)
	fw := getFirewall()

	for _, targetIP := range req.TargetIPs {
		msg := fmt.Sprintf("UDP flood detected: src=%s dst=%s dstport=%d rate=%d pps — blackholing", req.AttackerIP, targetIP, targetPort, pps)
		ev := sendSyslog(fw, msg, 1)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "UDP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		var sources []string
		for idx := 0; idx < 20; idx++ {
			sources = append(sources, fmt.Sprintf("198.51.%d.%d", rand.Intn(255), 1+rand.Intn(254)))
		}
		flows := FlowDDoS(sources, targetIP, targetPort, uint32(pps/20))
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPUDPFlood(req.RunID, targetIP, targetPort, sources[:10])
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealUDPBurst(targetIP, int(targetPort), 100)
	}

	logInfo("Return from runUDPFlood syslogs=%d flows=%d pcap=%d", result.SyslogCount, result.FlowCount, len(result.PCAPFiles))
	return result, nil
}

// runICMPFlood generates ICMP flood (Smurf) telemetry.
func runICMPFlood(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runICMPFlood attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()

	for _, targetIP := range req.TargetIPs {
		msg := fmt.Sprintf("Smurf attack: ICMP echo request flood src=%s dst=%s — rate=100k pps", req.AttackerIP, targetIP)
		ev := sendSyslog(fw, msg, 1)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "ICMP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: 0, DstPort: 0, Protocol: 1, Bytes: 6000000, Packets: 100000, StartTime: time.Now().Add(-30 * time.Second), EndTime: time.Now()}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "ICMP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}

	logInfo("Return from runICMPFlood syslogs=%d flows=%d", result.SyslogCount, result.FlowCount)
	return result, nil
}

// runHTTPFlood generates Layer 7 HTTP flood telemetry.
func runHTTPFlood(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runHTTPFlood attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	rps := getAttackParamInt(req.Params, "rps", 5000)
	fw := getFirewall()

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)

		// Web server access log
		if targetDev != nil && targetDev.Telemetry.Syslog {
			for idx := 0; idx < 10; idx++ {
				msg := fmt.Sprintf("%s - - [%s] \"GET / HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"",
					req.AttackerIP, time.Now().Format("02/Jan/2006:15:04:05 -0700"))
				ev := sendSyslog(targetDev, msg, 5)
				result.SyslogCount++
				eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
				result.EventIDs = append(result.EventIDs, eventID)
			}
		}

		// Firewall sees high connection rate
		fwMsg := fmt.Sprintf("HTTP flood: src=%s dst=%s rate=%d rps — WAF triggered", req.AttackerIP, targetIP, rps)
		ev := sendSyslog(fw, fwMsg, 2)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: uint32(rps * 500), Packets: uint32(rps), StartTime: time.Now().Add(-30 * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPHTTPFlood(req.RunID, req.AttackerIP, targetIP, 80, 20)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealHTTPFlood(targetIP, 80, rps)
	}

	logInfo("Return from runHTTPFlood syslogs=%d flows=%d pcap=%d", result.SyslogCount, result.FlowCount, len(result.PCAPFiles))
	return result, nil
}

// runSlowloris generates Slowloris slow-HTTP attack telemetry.
func runSlowloris(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSlowloris attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	connections := getAttackParamInt(req.Params, "connections", 200)
	fw := getFirewall()

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)

		if targetDev != nil && targetDev.Telemetry.Syslog {
			msg := fmt.Sprintf("Slowloris: %d half-open connections from %s — server unresponsive", connections, req.AttackerIP)
			ev := sendSyslog(targetDev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		// Many small TCP flows with long duration
		var flows []FlowRecord
		for idx := 0; idx < 20; idx++ {
			flows = append(flows, FlowRecord{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 200, Packets: 2, StartTime: time.Now().Add(-300 * time.Second), EndTime: time.Now(), TCPFlags: 0x02})
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPSlowloris(req.RunID, req.AttackerIP, targetIP, connections)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealSlowloris(targetIP, 80, connections)
	}

	logInfo("Return from runSlowloris syslogs=%d flows=%d pcap=%d", result.SyslogCount, result.FlowCount, len(result.PCAPFiles))
	return result, nil
}

// runAmplification generates DNS/NTP amplification attack telemetry.
func runAmplification(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runAmplification attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	proto := getAttackParam(req.Params, "proto", "dns")
	fw := getFirewall()
	dnsDev := getDNSServer()

	amplifier := "8.8.8.8"
	if proto == "dns" && dnsDev != nil {
		amplifier = dnsDev.IPAddress
	}

	for _, targetIP := range req.TargetIPs {
		// DNS server sees amplified query flood
		if dnsDev != nil && dnsDev.Telemetry.Syslog {
			msg := fmt.Sprintf("DNS amplification: excessive ANY queries from spoofed src=%s via %s — query flood", targetIP, amplifier)
			ev := sendSyslog(dnsDev, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", dnsDev.Name, amplifier, targetIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		fwMsg := fmt.Sprintf("Amplification attack: %s reflector sending 3000 bytes to %s (spoofed src)", amplifier, targetIP)
		ev := sendSyslog(fw, fwMsg, 1)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", amplifier, targetIP, "UDP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		flows := []FlowRecord{{SrcIP: amplifier, DstIP: targetIP, SrcPort: 53, DstPort: randomPort(), Protocol: 17, Bytes: 30000000, Packets: 10000, StartTime: time.Now().Add(-60 * time.Second), EndTime: time.Now()}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", amplifier, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}

	logInfo("Return from runAmplification syslogs=%d flows=%d", result.SyslogCount, result.FlowCount)
	return result, nil
}

func runHTTP2Reset(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runHTTP2Reset attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	streams := getAttackParamInt(req.Params, "streams", 10000)
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		msgs := []string{
			fmt.Sprintf("HTTP/2 Rapid Reset detected: src=%s dst=%s — %d RST_STREAM frames/sec (CVE-2023-44487)", req.AttackerIP, targetIP, streams),
			fmt.Sprintf("WAF: HTTP/2 stream exhaustion from %s — worker threads at 100%% capacity", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(fw, msg, 1)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 443, Protocol: 6, Bytes: uint32(streams * 50), Packets: uint32(streams * 2), StartTime: time.Now().Add(-30 * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runHTTP2Reset syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSSLExhaustion(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSSLExhaustion attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := getAttackParamInt(req.Params, "target_port", 443)
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		msgs := []string{
			fmt.Sprintf("TLS handshake flood from %s to %s:%d — CPU at 98%%, new handshakes rejected", req.AttackerIP, targetIP, targetPort),
			fmt.Sprintf("IDS: SSL exhaustion attack detected src=%s — 5000 incomplete handshakes/sec", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(fw, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		var flows []FlowRecord
		for idx := 0; idx < 20; idx++ {
			flows = append(flows, FlowRecord{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: uint16(targetPort), Protocol: 6, Bytes: 300, Packets: 3, StartTime: time.Now(), EndTime: time.Now().Add(time.Second), TCPFlags: 0x02})
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runSSLExhaustion syslogs=%d", result.SyslogCount)
	return result, nil
}

func runMemcachedAmp(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runMemcachedAmp attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	reflector := getAttackParam(req.Params, "reflector_ip", "10.0.0.100")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		msgs := []string{
			fmt.Sprintf("Memcached amplification: UDP/11211 reflector %s sending 100MB/s to %s (spoofed src)", reflector, targetIP),
			fmt.Sprintf("DOS alert: open Memcached reflector %s amplifying traffic to %s — 51200x factor", reflector, targetIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(fw, msg, 1)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", reflector, targetIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: reflector, DstIP: targetIP, SrcPort: 11211, DstPort: randomPort(), Protocol: 17, Bytes: 100000000, Packets: 20000, StartTime: time.Now().Add(-60 * time.Second), EndTime: time.Now()}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", reflector, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runMemcachedAmp syslogs=%d", result.SyslogCount)
	return result, nil
}

func runRUDY(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runRUDY attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	connections := getAttackParamInt(req.Params, "connections", 100)
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev != nil && targetDev.Telemetry.Syslog {
			msg := fmt.Sprintf("R.U.D.Y. attack: %d slow POST connections from %s — Content-Length declared but body sent 1 byte/10s", connections, req.AttackerIP)
			ev := sendSyslog(targetDev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		var flows []FlowRecord
		for idx := 0; idx < connections/5; idx++ {
			flows = append(flows, FlowRecord{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 50, Packets: 1, StartTime: time.Now().Add(-600 * time.Second), EndTime: time.Now(), TCPFlags: 0x18})
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runRUDY syslogs=%d", result.SyslogCount)
	return result, nil
}

func runACKFlood(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runACKFlood attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := uint16(getAttackParamInt(req.Params, "target_port", 80))
	pps := getAttackParamInt(req.Params, "pps", 20000)
	fw := getFirewall()
	var sources []string
	for idx := 0; idx < 30; idx++ {
		sources = append(sources, fmt.Sprintf("185.%d.%d.%d", rand.Intn(255), rand.Intn(255), 1+rand.Intn(254)))
	}
	for _, targetIP := range req.TargetIPs {
		msg := fmt.Sprintf("ACK flood detected: %d pps to %s:%d — connection table 98%% full, dropping new sessions", pps, targetIP, targetPort)
		ev := sendSyslog(fw, msg, 2)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
		flows := FlowDDoS(sources, targetIP, targetPort, uint32(pps/10))
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runACKFlood syslogs=%d", result.SyslogCount)
	return result, nil
}

func runRSTFlood(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runRSTFlood attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := uint16(getAttackParamInt(req.Params, "target_port", 443))
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		msgs := []string{
			fmt.Sprintf("TCP RST injection detected: forged RST packets targeting %s:%d — existing sessions terminated", targetIP, targetPort),
			fmt.Sprintf("IDS: TCP reset attack from %s — 500 established sessions disrupted", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(fw, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: targetPort, Protocol: 6, Bytes: 60000, Packets: 1000, StartTime: time.Now().Add(-10 * time.Second), EndTime: time.Now(), TCPFlags: 0x04}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
	}
	logInfo("Return from runRSTFlood syslogs=%d", result.SyslogCount)
	return result, nil
}
