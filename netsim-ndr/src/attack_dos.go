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
		// NEW
		totalPkts := uint32(pps * duration / 10) // per source (10 sources)
		flows := FlowDDoS(sources[:10], targetIP, targetPort, totalPkts)
		for i := range flows {
			flows[i].StartTime = time.Now().Add(-time.Duration(duration) * time.Second)
			flows[i].EndTime = time.Now()
			flows[i].Bytes = totalPkts * 60 // fixed 60 bytes per SYN packet
		}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP (Option B)
		path, _ := PCAPSYNFlood(req.RunID, targetIP, targetPort, sources, duration)
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
		duration := getAttackParamInt(req.Params, "duration", 30)
		totalPkts := uint32(pps * duration / len(sources))
		flows := FlowDDoS(sources, targetIP, targetPort, totalPkts)
		for i := range flows {
			flows[i].StartTime = time.Now().Add(-time.Duration(duration) * time.Second)
			flows[i].EndTime = time.Now()
			flows[i].Bytes = totalPkts * 1500 // fixed 1500 bytes per UDP packet
		}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "UDP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

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

		duration := getAttackParamInt(req.Params, "duration", 30)
		icmpPkts := uint32(100000 / 30 * duration) // 100k pps baseline
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: 0, DstPort: 0, Protocol: 1,
			Bytes: icmpPkts * 64, Packets: icmpPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now()}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "ICMP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		path, _ := PCAPICMPFlood(req.RunID, req.AttackerIP, targetIP, 100)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
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

		duration := getAttackParamInt(req.Params, "duration", 30)
		totalPkts := uint32(rps * duration)
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6,
			Bytes: totalPkts * 500, Packets: totalPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

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
		duration := getAttackParamInt(req.Params, "duration", 300)
		for idx := 0; idx < 20; idx++ {
			flows = append(flows, FlowRecord{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6,
				Bytes: 200, Packets: uint32(2 * duration / 300), // fixed 200 bytes, packets scale with duration
				StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x02})
		}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

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

		duration := getAttackParamInt(req.Params, "duration", 60)
		ampPkts := uint32(10000 / 60 * duration) // ~166 pps baseline
		flows := []FlowRecord{{SrcIP: amplifier, DstIP: targetIP, SrcPort: 53, DstPort: randomPort(), Protocol: 17,
			Bytes: ampPkts * 3000, Packets: ampPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now()}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", amplifier, targetIP, "UDP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
		ampPath, ampErr := PCAPUDPAmplification(req.RunID, amplifier, targetIP, 53, 3000)
		if ampErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, ampPath)
		}
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
		duration := getAttackParamInt(req.Params, "duration", 30)
		totalStreams := streams * duration
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 443, Protocol: 6,
			Bytes: uint32(totalStreams * 50), Packets: uint32(totalStreams * 2),
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
		h2Path, h2Err := PCAPGenericTCPExchange(req.RunID, "http2_reset", req.AttackerIP, targetIP, 443, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), nil)
		if h2Err == nil {
			result.PCAPFiles = append(result.PCAPFiles, h2Path)
		}
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
		duration := getAttackParamInt(req.Params, "duration", 30)
		sslFlowCount := 20 * duration / 30 // scale number of handshake flows with duration
		if sslFlowCount < 1 {
			sslFlowCount = 1
		}
		for idx := 0; idx < sslFlowCount; idx++ {
			flows = append(flows, FlowRecord{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: uint16(targetPort), Protocol: 6,
				Bytes: 300, Packets: 3, // fixed per-handshake size
				StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x02})
		}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
		sslPath, sslErr := PCAPGenericTCPExchange(req.RunID, "ssl_exhaustion", req.AttackerIP, targetIP, uint16(targetPort), buildMinimalTLSClientHello(), nil)
		if sslErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, sslPath)
		}
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
		duration := getAttackParamInt(req.Params, "duration", 60)
		mcPkts := uint32(20000 / 60 * duration) // ~333 pps baseline
		flows := []FlowRecord{{SrcIP: reflector, DstIP: targetIP, SrcPort: 11211, DstPort: randomPort(), Protocol: 17,
			Bytes: mcPkts * 5000, Packets: mcPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now()}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", reflector, targetIP, "UDP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
		mcPath, mcErr := PCAPUDPAmplification(req.RunID, reflector, targetIP, 11211, 1400)
		if mcErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, mcPath)
		}
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
		dev := targetDev
		if dev == nil {
			dev = fw
		}
		msg := fmt.Sprintf("R.U.D.Y. attack: %d slow POST connections from %s — Content-Length declared but body sent 1 byte/10s", connections, req.AttackerIP)
		ev := sendSyslog(dev, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		flowCount := connections / 5
		if flowCount < 1 {
			flowCount = 1
		}
		var flows []FlowRecord
		for idx := 0; idx < flowCount; idx++ {
			duration := getAttackParamInt(req.Params, "duration", 600)
			rudyPkts := uint32(duration / 10) // 1 packet every 10s — RUDY's defining characteristic
			if rudyPkts < 1 {
				rudyPkts = 1
			}
			flows = append(flows, FlowRecord{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6,
				Bytes: rudyPkts * 50, Packets: rudyPkts, // fixed 50 bytes per drip packet
				StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x18})
		}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
		rudyPath, rudyErr := PCAPGenericTCPExchange(req.RunID, "rudy", req.AttackerIP, targetIP, 80,
			[]byte("POST /login HTTP/1.1\r\nHost: target\r\nContent-Length: 10000\r\n\r\nX"), nil)
		if rudyErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, rudyPath)
		}
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
		duration := getAttackParamInt(req.Params, "duration", 30)
		totalPkts := uint32(pps * duration / len(sources))
		flows := FlowDDoS(sources, targetIP, targetPort, totalPkts)
		for i := range flows {
			flows[i].StartTime = time.Now().Add(-time.Duration(duration) * time.Second)
			flows[i].EndTime = time.Now()
			flows[i].Bytes = totalPkts * 60 // fixed 60 bytes per ACK packet
		}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
		ackPath, ackErr := PCAPACKFlood(req.RunID, targetIP, targetPort, sources)
		if ackErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, ackPath)
		}
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
		duration := getAttackParamInt(req.Params, "duration", 30)
		rstPkts := uint32(1000 / 10 * duration) // 100 pps baseline
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: targetPort, Protocol: 6,
			Bytes: rstPkts * 60, Packets: rstPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x04}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
		rstPath, rstErr := PCAPRSTFlood(req.RunID, req.AttackerIP, targetIP, targetPort, 20)
		if rstErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, rstPath)
		}
	}
	logInfo("Return from runRSTFlood syslogs=%d", result.SyslogCount)
	return result, nil
}
