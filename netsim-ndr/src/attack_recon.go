// Package main — attack_recon.go
// Reconnaissance attack module implementations.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// runPortScan simulates a TCP SYN port scan and generates syslog + flow + PCAP telemetry.
func runPortScan(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runPortScan attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	attackerDev, _ := getDeviceByIP(req.AttackerIP)
	if attackerDev == nil {
		attackerDev = getAttackerDevice()
	}
	portRange, _ := req.Params["port_range"]
	low_up := strings.Split(portRange, "-")
	if len(low_up) != 2 {
		// port_range missing or malformed (e.g. when a scenario launches this
		// attack without specifying it) — fall back to a sensible default range.
		low_up = []string{"1", "1024"}
	}
	lower_range, err := strconv.Atoi(strings.TrimSpace(low_up[0]))
	if err != nil {
		lower_range = 1
	}
	upper_range, err := strconv.Atoi(strings.TrimSpace(low_up[1]))
	if err != nil {
		upper_range = 1024
	}
	if lower_range > upper_range {
		lower_range, upper_range = upper_range, lower_range
	}
	ports := make([]uint16, 0)
	for p := lower_range; p <= upper_range; p++ {
		ports = append(ports, uint16(p))
	}

	duration, _ := strconv.ParseUint(req.Params["rate"], 10, 64)
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}

		port_mapping := make(map[uint16]string)
		for _, port := range ports {
			num := rand.Intn(1000)
			if num == 90 {
				port_mapping[port] = "Open"
			} else {
				port_mapping[port] = "Close"
			}
		}
		var wg sync.WaitGroup
		wg.Add(3)
		// Syslog
		go func(result *AttackResult) {
			defer wg.Done()
			syslogEvents := SyslogPortScan(attackerDev.IPAddress, targetIP, ports, port_mapping, duration)
			result.SyslogCount += len(syslogEvents)
			for _, ev := range syslogEvents {
				eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, attackerDev.IPAddress, targetIP, "TCP", ev)
				result.EventIDs = append(result.EventIDs, eventID)
			}
		}(result)

		// Flows
		go func(result *AttackResult) {
			defer wg.Done()
			flows := FlowScan(attackerDev.IPAddress, targetIP, ports, duration)
			result.FlowCount += len(flows)
			fw := getFirewall()
			if fw != nil && fw.Telemetry.Netflow {
				ExportNetflowV9(fw.IPAddress, flows)
			}
			flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", attackerDev.IPAddress, targetIP, "TCP", flows)
			result.EventIDs = append(result.EventIDs, flowID)
		}(result)

		// PCAP (Option B — always generate)
		go func(result *AttackResult) {
			defer wg.Done()
			_, path, err := PCAPPortScan(attackerDev, targetDev, ports, port_mapping)
			if err == nil && path != "" {
				result.PCAPFiles = append(result.PCAPFiles, path)
			}
		}(result)
		wg.Wait()

		// Real packets (Option A — on-wire SYN scan if enabled)
		//go sendRealPortScanTCP(targetIP, ports)

	}

	logInfo("Return from runPortScan syslogs=%d flows=%d pcap=%d", result.SyslogCount, result.FlowCount, len(result.PCAPFiles))
	return result, nil
}

// runOSFingerprint simulates OS fingerprinting probe traffic.
func runOSFingerprint(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runOSFingerprint attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	attackerDev, _ := getDeviceByIP(req.AttackerIP)
	if attackerDev == nil {
		attackerDev = getAttackerDevice()
	}
	fw := getFirewall()

	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)

		// Syslog: firewall sees unusual TCP flag combinations
		var message []string = []string{
			// TCP probes
			fmt.Sprintf("connection from %s to %s port 80 TCP SYN ACCEPTED", req.AttackerIP, targetIP),
			fmt.Sprintf("connection from %s to %s port 80 TCP SYN ACCEPTED", req.AttackerIP, targetIP),
			fmt.Sprintf("connection from %s to %s port 80 TCP SYN ACCEPTED", req.AttackerIP, targetIP),
			fmt.Sprintf("connection from %s to %s port 80 TCP SYN ACCEPTED", req.AttackerIP, targetIP),
			fmt.Sprintf("connection from %s to %s port 80 TCP SYN ACCEPTED", req.AttackerIP, targetIP),
			fmt.Sprintf("connection from %s to %s port 80 TCP SYN ACCEPTED", req.AttackerIP, targetIP),
			// ICMP Echo Requests
			fmt.Sprintf("ICMP echo request from %s to %s port 40 of payload 10B", req.AttackerIP, targetIP),
			fmt.Sprintf("ICMP echo request from %s to %s port 40 of payload 30B", req.AttackerIP, targetIP),
			// EWN+CWR
			fmt.Sprintf("PROBE detected src=%s dst=%s: TCP SYN+EWN+CWR flags (OS fingerprint probe)", req.AttackerIP, targetIP),
			// T2-T7 probes
			fmt.Sprintf("PROBE detected src=%s dst=%s: TCP NULL flag and DF bit set (OS fingerprint probe)", req.AttackerIP, targetIP),
			fmt.Sprintf("PROBE detected src=%s dst=%s: TCP SYN+FIN+URG+PSH flags and DF bit not set (OS fingerprint probe)", req.AttackerIP, targetIP),
			fmt.Sprintf("PROBE detected src=%s dst=%s: TCP ACK flag and DF bit set on open port with no session (OS fingerprint probe)", req.AttackerIP, targetIP),
			fmt.Sprintf("connection from %s to %s port 60 TCP SYN DENIED", req.AttackerIP, targetIP),
			fmt.Sprintf("PROBE detected src=%s dst=%s: TCP ACK flag on closed port 60 (OS fingerprint probe)", req.AttackerIP, targetIP),
			fmt.Sprintf("PROBE detected src=%s dst=%s: TCP FIN+URG+PSH flags with DF bit set (OS fingerprint probe)", req.AttackerIP, targetIP),
			// UDP probe
			fmt.Sprintf("PROBE detected src=%s dst=%s: UDP probe with payload size 150MB to closed port 60 (OS fingerprint probe)", req.AttackerIP, targetIP),
		}
		severity_score := []int{5, 5, 5, 5, 5, 5, 4, 4, 3, 3, 2, 3, 5, 3, 2, 4}
		for i, msg := range message {
			if fw != nil {
				ev := sendSyslog(fw, msg, severity_score[i])
				result.SyslogCount++
				eventID, _ := recordRunEvent(req.RunID, "syslog", fw.Name, req.AttackerIP, targetIP, "TCP", ev)
				result.EventIDs = append(result.EventIDs, eventID)
			}
		}

		// Flows: small high-variety packets
		probeFlows := []FlowRecord{
			//TCP probes
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(100 * time.Millisecond), TCPFlags: 0x02},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(100 * time.Millisecond), TCPFlags: 0x02},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(100 * time.Millisecond), TCPFlags: 0x02},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(100 * time.Millisecond), TCPFlags: 0x02},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(100 * time.Millisecond), TCPFlags: 0x02},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(100 * time.Millisecond), TCPFlags: 0x02},
			// ICMP probes
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 1, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x00},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 1, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x00},
			// ECN+CWR
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0xC2},
			// T2-T7 probes
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x00},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x31},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x10},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x02},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x10},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x29},
			// UDP probe
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 80, Protocol: 17, Bytes: 60, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Millisecond), TCPFlags: 0x00},
		}
		if fw != nil {
			ExportNetflowV9(fw.IPAddress, probeFlows)
		}
		result.FlowCount += len(probeFlows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", probeFlows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP with unusual TCP flag combinations (always generate)
		if targetDev != nil {
			srcMAC := parseMACAddress(attackerDev.MACAddress)
			dstMAC := parseMACAddress(targetDev.MACAddress)
			var frames [][]byte
			ICMP_probe_done := false
			response := []uint8{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x52, 0x04, 0x14, 0x04, 0x04}
			for i, flags := range []uint8{0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0xC2, 0x00, 0x31, 0x10, 0x29} {
				seq := rand.Uint32()
				src_port := randomPort()
				if i == 6 && !ICMP_probe_done {
					// ICMP probe 1
					payload1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
					ICMPrequest1 := buildICMPSegment(8, 0, 0x485C, 0x0100, 0x0001, payload1)
					ipPktreq1 := buildIPv4Packet(req.AttackerIP, targetIP, 1, ICMPrequest1)
					framereq1 := buildEthernetFrame(srcMAC, dstMAC, ipPktreq1)
					frames = append(frames, framereq1)
					// ICMP probe 1 response
					ICMPreply1 := buildICMPSegment(0, 0, 0x505C, 0x0100, 0x0001, payload1)
					ipPktreply1 := buildIPv4Packet(req.AttackerIP, targetIP, 1, ICMPreply1)
					framereply1 := buildEthernetFrame(srcMAC, dstMAC, ipPktreply1)
					frames = append(frames, framereply1)
					// ICMP probe 2
					payload2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
					ICMPrequest2 := buildICMPSegment(8, 0, 0x485C, 0x0100, 0x0001, payload2)
					ipPktreq2 := buildIPv4Packet(req.AttackerIP, targetIP, 1, ICMPrequest2)
					framereq2 := buildEthernetFrame(srcMAC, dstMAC, ipPktreq2)
					frames = append(frames, framereq2)
					// ICMP probe 2 response
					ICMPreply2 := buildICMPSegment(0, 0, 0x505C, 0x0100, 0x0001, payload2)
					ipPktreply2 := buildIPv4Packet(req.AttackerIP, targetIP, 1, ICMPreply2)
					framereply2 := buildEthernetFrame(srcMAC, dstMAC, ipPktreply2)
					frames = append(frames, framereply2)
					ICMP_probe_done = true
				}
				// Sending packets with various TCP flag combinations for OS fingerprinting
				tcpflagged := buildTCPSegment(src_port, 80, flags, seq, 0, nil)
				ipPkt := buildIPv4Packet(req.AttackerIP, targetIP, 6, tcpflagged)
				frame := buildEthernetFrame(srcMAC, dstMAC, ipPkt)
				frames = append(frames, frame)
				// Sending expected responses with corresponding TCP flags
				tcpResponse := buildTCPSegment(80, src_port, response[i], 1, seq+1, nil)
				ipPktres := buildIPv4Packet(targetIP, req.AttackerIP, 6, tcpResponse)
				frameres := buildEthernetFrame(srcMAC, dstMAC, ipPktres)
				frames = append(frames, frameres)
			}
			src_port := randomPort()
			payload := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
			udp_datagram := buildUDPDatagram(src_port, 60, payload)
			ipPkt := buildIPv4Packet(req.AttackerIP, targetIP, 17, udp_datagram)
			frame := buildEthernetFrame(srcMAC, dstMAC, ipPkt)
			frames = append(frames, frame)
			path, _ := writePCAPFile(req.RunID, "os_fingerprint", frames, defaultDuration)
			if path != "" {
				result.PCAPFiles = append(result.PCAPFiles, path)
			}
		}

		// Real packets (Option A)
		go sendRealServiceProbe(targetIP, 80)
	}

	logInfo("Return from runOSFingerprint syslogs=%d flows=%d", result.SyslogCount, result.FlowCount)
	return result, nil
}
func create_TCP_frame(src_port, dst_port uint16, flags uint8, seq, ack uint32, src_ip, target_ip string, srcMAC, dstMAC [6]byte, payload []byte) []byte {
	tcpflagged := buildTCPSegment(src_port, dst_port, flags, seq, ack, payload)
	ipPkt := buildIPv4Packet(src_ip, target_ip, 6, tcpflagged)
	frame := buildEthernetFrame(srcMAC, dstMAC, ipPkt)
	return frame
}

// runServiceEnum simulates SMB/SNMP service enumeration.
func runServiceEnum(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runServiceEnum attacker=%s targets=%v", req.AttackerIP, req.TargetIPs)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	attackerDev, _ := getDeviceByIP(req.AttackerIP)
	if attackerDev == nil {
		attackerDev = getAttackerDevice()
	}
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		if targetDev == nil {
			continue
		}
		src_port := randomPort()
		// SMB NULL session enumeration syslog
		msgs := []string{
			fmt.Sprintf("SMB Session started from %s to %s", req.AttackerIP, targetIP),
			fmt.Sprintf("SMB NULL connection established between %s and %s", req.AttackerIP, targetIP),
			fmt.Sprintf("SMB IPC$ connection established between %s and %s", req.AttackerIP, targetIP),
			fmt.Sprintf("SMB IOCTL connection established between %s and %s", req.AttackerIP, targetIP),
			fmt.Sprintf("SNMP community string 'public' queried by %s from %s", req.AttackerIP, targetIP),
			fmt.Sprintf("NetBIOS name query from %s to %s", req.AttackerIP, targetIP),
		}
		for i, msg := range msgs {
			ev := sendSyslog(targetDev, msg, 5)
			result.SyslogCount++
			if i < 4 {
				eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
				result.EventIDs = append(result.EventIDs, eventID)
			} else {
				eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "UDP", ev)
				result.EventIDs = append(result.EventIDs, eventID)
			}

		}

		// Flows
		enumFlows := []FlowRecord{
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: src_port, DstPort: 445, Protocol: 6, Bytes: 5000, Packets: 12, StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second)},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: src_port, DstPort: 161, Protocol: 17, Bytes: 500, Packets: 2, StartTime: time.Now(), EndTime: time.Now().Add(time.Second)},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: src_port, DstPort: 161, Protocol: 17, Bytes: 500, Packets: 2, StartTime: time.Now(), EndTime: time.Now().Add(time.Second)},
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, enumFlows)
		}
		result.FlowCount += len(enumFlows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "UDP+TCP", enumFlows)
		result.EventIDs = append(result.EventIDs, flowID)

		seq := rand.Uint32()
		srcMAC := parseMACAddress(attackerDev.MACAddress)
		dstMAC := parseMACAddress(targetDev.MACAddress)
		var frames [][]byte
		// SMB enumeration
		// SYN
		frames = append(frames, create_TCP_frame(src_port, 445, 0x02, seq, 0, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))
		// SYN-ACK
		frames = append(frames, create_TCP_frame(445, src_port, 0x12, 0, seq+1, targetIP, req.AttackerIP, dstMAC, srcMAC, nil))
		// ACK
		frames = append(frames, create_TCP_frame(src_port, 445, 0x02, seq+1, 1, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))
		// SMB client start session
		frames = append(frames, create_TCP_frame(src_port, 445, 0x12, seq+2, 1, req.AttackerIP, targetIP, srcMAC, dstMAC, SMB2_Negotiate_request))
		// SMB server response session
		frames = append(frames, create_TCP_frame(445, src_port, 0x12, 1, seq+3, targetIP, req.AttackerIP, dstMAC, srcMAC, SMB2_Negotiate_Response))
		// Null Session client
		frames = append(frames, create_TCP_frame(src_port, 445, 0x12, seq+3, 2, req.AttackerIP, targetIP, srcMAC, dstMAC, SMB2_Session_Setup_Request_Null))
		// Null Session server
		frames = append(frames, create_TCP_frame(445, src_port, 0x12, 2, seq+4, targetIP, req.AttackerIP, dstMAC, srcMAC, SMB2_Session_Setup_Response_Null))
		// IPC$ connection client
		frames = append(frames, create_TCP_frame(src_port, 445, 0x12, seq+4, 3, req.AttackerIP, targetIP, srcMAC, dstMAC, SMB2_TreeConnect_Request_IPC))
		// IPC$ connection server
		frames = append(frames, create_TCP_frame(445, src_port, 0x12, 3, seq+5, targetIP, req.AttackerIP, dstMAC, srcMAC, SMB2_TreeConnect_Response_IPC))
		// IOCTL connection client
		frames = append(frames, create_TCP_frame(src_port, 445, 0x12, seq+5, 4, req.AttackerIP, targetIP, srcMAC, dstMAC, SMB2_IOCTL_Request_NetShareEnumAll))
		// IOCTL connection server
		frames = append(frames, create_TCP_frame(445, src_port, 0x12, 4, seq+6, targetIP, req.AttackerIP, dstMAC, srcMAC, SMB2_IOCTL_Response_NetShareEnumAll))
		// ACK
		frames = append(frames, create_TCP_frame(src_port, 445, 0x02, seq+6, 5, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))

		// SNMP query
		SNMP_query := buildUDPDatagram(src_port, 161, SNMP_GetRequest)
		ipPkt_q := buildIPv4Packet(req.AttackerIP, targetIP, 17, SNMP_query)
		frame_q := buildEthernetFrame(srcMAC, dstMAC, ipPkt_q)
		frames = append(frames, frame_q)
		// SNMP response
		SNMP_response := buildUDPDatagram(161, src_port, SNMP_GetRequest)
		ipPkt_r := buildIPv4Packet(targetIP, req.AttackerIP, 17, SNMP_response)
		frame_r := buildEthernetFrame(dstMAC, srcMAC, ipPkt_r)
		frames = append(frames, frame_r)

		// NetBIOS query
		NetBIOS_query := buildUDPDatagram(src_port, 137, NBNS_Name_Query_Request)
		ipPkt_nq := buildIPv4Packet(req.AttackerIP, targetIP, 137, NetBIOS_query)
		frame_nq := buildEthernetFrame(srcMAC, dstMAC, ipPkt_nq)
		frames = append(frames, frame_nq)
		// NetBIOS response
		NetBIOS_response := buildUDPDatagram(137, src_port, Get_NBNS_Response(targetIP))
		ipPkt_nr := buildIPv4Packet(targetIP, req.AttackerIP, 137, NetBIOS_response)
		frame_nr := buildEthernetFrame(dstMAC, srcMAC, ipPkt_nr)
		frames = append(frames, frame_nr)

		path, _ := writePCAPFile(req.RunID, "service_enumeration", frames, defaultDuration)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}

	logInfo("Return from runServiceEnum syslogs=%d flows=%d", result.SyslogCount, result.FlowCount)
	return result, nil
}

func EncodeDomainName(domain string) ([]byte, error) {
	var buf bytes.Buffer
	// Remove trailing dot if present to avoid empty label at end
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	for _, label := range parts {
		lenLabel := len(label)
		if lenLabel == 0 {
			continue // Skip empty parts (e.g. double dots)
		}
		if lenLabel > 63 {
			return nil, errors.New("label too long: max 63 chars")
		}
		// 1. Write Length Byte
		buf.WriteByte(byte(lenLabel))
		// 2. Write Label Bytes
		buf.WriteString(label)
	}
	// 3. Write Root Terminator
	buf.WriteByte(0x00)
	return buf.Bytes(), nil
}

func encodable_domain(domain string) [][]byte {
	encoding, _ := EncodeDomainName(domain)
	var results [][]byte
	i := 0
	length := int(encoding[i])
	for i < len(encoding) {
		result := encoding[i+1 : i+length+1]
		if len(result) > 0 {
			results = append(results, result)
		}
		i = i + length + 1
		if i >= len(encoding) {
			return results
		}
		length = int(encoding[i])
	}
	return results
}

// prefixDNSTCPLength prepends the 2-byte big-endian length DNS-over-TCP
// requires before the message. Without this, tcpdump/Wireshark misreads
// the first 2 bytes of the DNS message itself (the transaction ID) as the
// length field, producing "[prefix length(...) != length(...)] (invalid)".
func prefixDNSTCPLength(msg []byte) []byte {
	length := uint16(len(msg))
	return append([]byte{byte(length >> 8), byte(length)}, msg...)
}
func buildAXFRRequestPayload(domain string) []byte {

	payload := []byte{
		0x4A, 0x2B, // # ID: Transaction ID (0x4A2B)
		0x01, 0x00, // # Flags: 0x0100 (QR=0 Query, Opcode=0, RD=1)
		0x00, 0x01, // # QDCOUNT: 1 Question
		0x00, 0x00, // # ANCOUNT: 0 Answers
		0x00, 0x00, // # NSCOUNT: 0 Authority
		0x00, 0x00, // # ARCOUNT: 0 Additional
		// # QNAME Length: 7 bytes
		// # QNAME: "example" (ASCII)
		//# QNAME Length: 3 bytes
		//# QNAME: "com" (ASCII)
	}
	domain_encoded := encodable_domain(domain)
	for _, encoding := range domain_encoded {
		payload = append(payload, byte(len(encoding)))
		for _, bytecode := range encoding {
			payload = append(payload, bytecode)
		}
	}
	rest_of_payload := []byte{
		0x00,       //# QNAME End: Null terminator
		0x00, 0xFC, //# QTYPE: 252 (AXFR)
		0x00, 0x01, //# QCLASS: 1 (IN),
	}
	for _, bytecode := range rest_of_payload {
		payload = append(payload, bytecode)
	}
	return prefixDNSTCPLength(payload)
}

func buildAXFRResponsePayload(domain string) []byte {
	payload := []byte{
		0x4A, 0x2B, // # ID: Transaction ID (0x4A2B)
		0x81, 0x00, // # Flags: 0x0100 (QR=0 Query, Opcode=0, RD=1)
		0x00, 0x01, // # QDCOUNT: 1 Question
		0x00, 0x01, // # ANCOUNT: 0 Answers
		0x00, 0x00, // # NSCOUNT: 0 Authority
		0x00, 0x00, // # ARCOUNT: 0 Additional
	}
	domain_encoded := encodable_domain(domain)
	for _, encoding := range domain_encoded {
		payload = append(payload, byte(len(encoding)))
		for _, bytecode := range encoding {
			payload = append(payload, bytecode)
		}
	}
	rest_of_payload := []byte{
		0x00,       //# QNAME End: Null terminator
		0x00, 0xFC, //# QTYPE: 252 (AXFR)
		0x00, 0x01, //# QCLASS: 1 (IN),
		// # --- Answer Section (SOA Record) ---
		0xC0, 0x0C, //# NAME: Pointer to offset 12 ("example.com")
		0x00, 0x06, //# TYPE: 6 (SOA)
		0x00, 0x01, //# CLASS: 1 (IN)
		0x00, 0x00, 0x0E, 0x10, //# TTL: 3600 seconds
		0x00, 0x3E, //# RDLENGTH: 62 bytes (Size of RDATA)
		// # --- RDATA (SOA Specifics) ---
		0x03, 0x6E, 0x73, 0x31, //# MNAME Len + "ns1"
		0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, //# "example"
		0x03, 0x63, 0x6F, 0x6D, 0x00, //# "com." + Null (Primary NS: ns1.example.com)
		0x05, 0x61, 0x64, 0x6D, 0x69, 0x6E, //# RNAME Len + "admin"
		0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, //# "example"
		0x03, 0x63, 0x6F, 0x6D, 0x00, //# "com." + Null (Admin: admin.example.com)
		0x78, 0x9A, 0x4C, 0x01, //# SERIAL: 2026052601
		0x00, 0x00, 0x0E, 0x10, //# REFRESH: 3600
		0x00, 0x00, 0x02, 0x58, //# RETRY: 600
		0x00, 0x09, 0x3A, 0x80, //# EXPIRE: 604800
		0x00, 0x00, 0x0E, 0x10, //# MINIMUM: 3600
	}
	for _, bytecode := range rest_of_payload {
		payload = append(payload, bytecode)
	}
	return prefixDNSTCPLength(payload)
}

// runDNSRecon simulates DNS zone transfer and enumeration.
func runDNSRecon(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runDNSRecon attacker=%s", req.AttackerIP)
	fw := getFirewall()
	attackDev, _ := getDeviceByIP(req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	domain := getAttackParam(req.Params, "domain", "corp.local")
	dnsDev := getDNSServer()
	if dnsDev == nil {
		return result, fmt.Errorf("no DNS server in topology")
	}
	src_port := randomPort()
	// DNS zone transfer attempt (AXFR)
	axfrMsg := fmt.Sprintf("client %s#%d: zone transfer 'AXFR' for zone '%s' accepted", req.AttackerIP, src_port, domain)
	ev := sendSyslog(dnsDev, axfrMsg, 3)
	result.SyslogCount++
	eventID, _ := recordRunEvent(req.RunID, "syslog", dnsDev.Name, req.AttackerIP, dnsDev.IPAddress, "TCP", ev)
	result.EventIDs = append(result.EventIDs, eventID)

	// DNS brute-force subdomains
	var queries [][]byte
	var queryPorts []uint16
	subdomains := []string{"mail", "vpn", "dc", "admin", "dev", "stage", "prod", "backup"}
	for _, sub := range subdomains {
		queryPort := randomPort()
		qMsg := fmt.Sprintf("client %s#%d: query: %s.%s IN A + (%s)",
			req.AttackerIP, queryPort, sub, domain, dnsDev.IPAddress)
		ev := sendSyslog(dnsDev, qMsg, 6)
		queries = append(queries, buildDNSQuery(fmt.Sprintf("%s.%s", domain, sub)))
		queryPorts = append(queryPorts, queryPort)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", dnsDev.Name, req.AttackerIP, dnsDev.IPAddress, "UDP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
		time.Sleep(20 * time.Millisecond)
	}
	enumFlows := []FlowRecord{
		{SrcIP: req.AttackerIP, DstIP: dnsDev.IPAddress, SrcPort: src_port, DstPort: 53, Protocol: 6, Bytes: 5000, Packets: 14, StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second)},
	}
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, enumFlows)
	}
	result.FlowCount += len(enumFlows)
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, dnsDev.IPAddress, "UDP+TCP", enumFlows)
	result.EventIDs = append(result.EventIDs, flowID)

	// PCAP for DNS recon (always generate)
	{
		var frames [][]byte
		srcMAC := parseMACAddress(attackDev.MACAddress)
		dstMAC := parseMACAddress(dnsDev.MACAddress)
		seq := rand.Uint32()
		// TCP Handshake
		clientSeq := seq
		serverSeq := uint32(0)
		frames = append(frames, create_TCP_frame(src_port, 53, 0x02, clientSeq, 0, req.AttackerIP, dnsDev.IPAddress, srcMAC, dstMAC, nil))
		clientSeq++
		frames = append(frames, create_TCP_frame(53, src_port, 0x12, serverSeq, clientSeq, req.AttackerIP, dnsDev.IPAddress, dstMAC, srcMAC, nil))
		serverSeq++
		frames = append(frames, create_TCP_frame(src_port, 53, 0x10, clientSeq, serverSeq, req.AttackerIP, dnsDev.IPAddress, srcMAC, dstMAC, nil))

		// AXFR request
		axfr := buildAXFRRequestPayload(domain)
		frames = append(frames, create_TCP_frame(src_port, 53, 0x18, clientSeq, serverSeq, req.AttackerIP, dnsDev.IPAddress, srcMAC, dstMAC, axfr))
		clientSeq += uint32(len(axfr))
		frames = append(frames, create_TCP_frame(53, src_port, 0x10, serverSeq, clientSeq, req.AttackerIP, dnsDev.IPAddress, dstMAC, srcMAC, nil))

		// AXFR response
		response := buildAXFRResponsePayload(domain)
		frames = append(frames, create_TCP_frame(53, src_port, 0x18, serverSeq, clientSeq, req.AttackerIP, dnsDev.IPAddress, dstMAC, srcMAC, response))
		serverSeq += uint32(len(response))
		frames = append(frames, create_TCP_frame(src_port, 53, 0x10, clientSeq, serverSeq, req.AttackerIP, dnsDev.IPAddress, srcMAC, dstMAC, nil))

		// Additional AXFR response segments
		frames = append(frames, create_TCP_frame(53, src_port, 0x18, serverSeq, clientSeq, req.AttackerIP, dnsDev.IPAddress, dstMAC, srcMAC, AXFRTCPResponse2))
		serverSeq += uint32(len(AXFRTCPResponse2))
		frames = append(frames, create_TCP_frame(src_port, 53, 0x10, clientSeq, serverSeq, req.AttackerIP, dnsDev.IPAddress, srcMAC, dstMAC, nil))

		frames = append(frames, create_TCP_frame(53, src_port, 0x18, serverSeq, clientSeq, req.AttackerIP, dnsDev.IPAddress, dstMAC, srcMAC, AXFRTCPResponse3))
		serverSeq += uint32(len(AXFRTCPResponse3))
		frames = append(frames, create_TCP_frame(src_port, 53, 0x10, clientSeq, serverSeq, req.AttackerIP, dnsDev.IPAddress, srcMAC, dstMAC, nil))

		// Connection teardown
		frames = append(frames, create_TCP_frame(src_port, 53, 0x01, clientSeq, serverSeq, req.AttackerIP, dnsDev.IPAddress, srcMAC, dstMAC, nil))
		clientSeq++
		frames = append(frames, create_TCP_frame(53, src_port, 0x10, serverSeq, clientSeq, req.AttackerIP, dnsDev.IPAddress, dstMAC, srcMAC, nil))
		frames = append(frames, create_TCP_frame(53, src_port, 0x01, serverSeq, clientSeq, req.AttackerIP, dnsDev.IPAddress, dstMAC, srcMAC, nil))
		serverSeq++
		frames = append(frames, create_TCP_frame(src_port, 53, 0x10, clientSeq, serverSeq, req.AttackerIP, dnsDev.IPAddress, srcMAC, dstMAC, nil))
		for i, query := range queries {
			udp := buildUDPDatagram(queryPorts[i], 53, query)
			ip := buildIPv4Packet(req.AttackerIP, dnsDev.IPAddress, 17, udp)
			frames = append(frames, buildEthernetFrame(srcMAC, dstMAC, ip))
		}
		path, _ := writePCAPFile(req.RunID, "dns_recon", frames, 50)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	// Real packets (Option A)
	go sendRealDNSQuery(dnsDev.IPAddress, domain, 1)

	logInfo("Return from runDNSRecon syslogs=%d", result.SyslogCount)
	return result, nil
}

func get_IPs_from_subnet(IPAddress string) []string {
	var result []string
	if strings.Contains(IPAddress, "/") {
		p, err := netip.ParsePrefix(IPAddress)
		if err != nil {
			log.Fatal(err)
		}
		p = p.Masked()
		addr := p.Addr()
		for {
			if !p.Contains(addr) {
				break
			}
			result = append(result, addr.String())
			addr = addr.Next()
		}
	} else {
		result = append(result, IPAddress)
	}
	return result
}

// runNetDiscover simulates an ARP sweep to enumerate live hosts.
func runNetDiscover(req AttackRequest) (*AttackResult, error) {

	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runNetDiscover attacker=%s", req.AttackerIP)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	switches := getSwitches()
	switches = append(switches, getRouters()...)
	if len(switches) == 0 {
		return result, nil
	}

	for _, targetIP := range req.TargetIPs {
		var point int
		var got_switch bool = false
		var sw *Device = nil
		var subnet string
		// Identifying subnet and corresponding router
		if strings.ContainsRune(targetIP, '/') {
			for i := len(targetIP) - 1; i > 0; i-- {
				if targetIP[i] == '/' {
					subnet = targetIP[:i-1]
					break
				} else if targetIP[i] == '.' {
					subnet = targetIP[:i]
				}
			}
		}
		for i, switchDev := range switches {
			if strings.Contains(switchDev.IPAddress, subnet) {
				point = i
				got_switch = true
				break
			}
		}
		sw = switches[point]
		if !got_switch {
			continue
		}
		targets := get_IPs_from_subnet(targetIP)
		// Syslogs
		var frames [][]byte
		for _, ip := range targets {
			msg := fmt.Sprintf("ARP request: who-has %s tell %s", ip, req.AttackerIP)
			ev := sendSyslog(sw, msg, 7)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", sw.Name, req.AttackerIP, targetIP, "ARP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
			// sFlow samples from switch
			arpFlows := []FlowRecord{
				{SrcIP: req.AttackerIP, DstIP: ip, SrcPort: 0, DstPort: 0, Protocol: 1, Bytes: 280, Packets: 1, StartTime: time.Now(), EndTime: time.Now().Add(time.Second)},
			}
			if sw.Telemetry.Sflow {
				ExportSflow(sw, arpFlows)
				result.FlowCount++
				flowID, _ := recordRunEvent(req.RunID, "sflow", sw.Name, req.AttackerIP, ip, "ARP", arpFlows)
				result.EventIDs = append(result.EventIDs, flowID)
			}
			// PCAP
			srcMAC := parseMACAddress(req.AttackerIP)
			ARPRequest := buildARPRequest(srcMAC, req.AttackerIP, ip)
			broadMAC := parseMACAddress("FF:FF:FF:FF:FF:FF")
			requestframe := buildEthernetFrameARP(srcMAC, broadMAC, ARPRequest, 0x0806)
			frames = append(frames, requestframe)
			dev, res := getDeviceByIP(ip)
			if res {
				targetMAC := parseMACAddress(dev.MACAddress)
				ARPReply := buildARPReply(srcMAC, targetMAC, req.AttackerIP, ip)
				requestframe := buildEthernetFrameARP(targetMAC, srcMAC, ARPReply, 0x0806)
				frames = append(frames, requestframe)
			}
		}
		path, _ := writePCAPFile(req.RunID, "ARP_scan", frames, defaultDuration)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}

	logInfo("Return from runNetDiscover syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSNMPEnum(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSNMPEnum attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	community := getAttackParam(req.Params, "community", "public")
	fw := getFirewall()
	attackerDev, _ := getDeviceByIP(req.AttackerIP)
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		msgs := []string{
			fmt.Sprintf("SNMP query from %s community='%s' OID=1.3.6.1.2.1.1.1.0 (sysDescr)", req.AttackerIP, community),
			fmt.Sprintf("SNMP walk from %s on %s: 1.3.6.1.2.1.2 (ifTable) — 12 interfaces enumerated", req.AttackerIP, targetIP),
			fmt.Sprintf("SNMP community '%s' accepted on %s — routing table exposed via 1.3.6.1.2.1.4.21", community, targetIP),
		}
		dev := targetDev
		if dev == nil {
			dev = fw
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 5)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 161, Protocol: 17, Bytes: 2400, Packets: 30, StartTime: time.Now(), EndTime: time.Now().Add(3 * time.Second)}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		if attackerDev == nil || dev == nil {
			logWarn("runSNMPEnum target=%s: no device with MAC address available, skipping PCAP", targetIP)
			continue
		}

		// PCAP
		srcMAC := parseMACAddress(attackerDev.MACAddress)
		dstMAC := parseMACAddress(dev.MACAddress)
		src_port := randomPort()
		var frames [][]byte
		// SNMP query
		SNMP_query := buildUDPDatagram(src_port, 161, SNMPQuery(community))
		ipPkt_q := buildIPv4Packet(req.AttackerIP, targetIP, 17, SNMP_query)
		frame_q := buildEthernetFrame(srcMAC, dstMAC, ipPkt_q)
		frames = append(frames, frame_q)
		// SNMP response
		SNMP_response := buildUDPDatagram(161, src_port, SNMPresponse(community))
		ipPkt_r := buildIPv4Packet(targetIP, req.AttackerIP, 17, SNMP_response)
		frame_r := buildEthernetFrame(dstMAC, srcMAC, ipPkt_r)
		frames = append(frames, frame_r)
		for i := 0; i < 5; i++ {
			// SNMP query
			SNMP_query := buildUDPDatagram(src_port, 161, SNMPGetNextResponse(community))
			ipPkt_q := buildIPv4Packet(req.AttackerIP, targetIP, 17, SNMP_query)
			frame_q := buildEthernetFrame(srcMAC, dstMAC, ipPkt_q)
			frames = append(frames, frame_q)
			// SNMP response
			SNMP_response := buildUDPDatagram(161, src_port, SNMPReplyNextResponse(community))
			ipPkt_r := buildIPv4Packet(targetIP, req.AttackerIP, 17, SNMP_response)
			frame_r := buildEthernetFrame(dstMAC, srcMAC, ipPkt_r)
			frames = append(frames, frame_r)
		}
		path, _ := writePCAPFile(req.RunID, "SNMP_enum", frames, defaultDuration)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runSNMPEnum syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSMTPUserEnum(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSMTPUserEnum attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	domain := getAttackParam(req.Params, "domain", "corp.local")
	fw := getFirewall()
	users := []string{"admin", "administrator", "root", "postmaster", "john.doe", "jane.smith", "support", "sales"}
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		for _, user := range users {
			msg := fmt.Sprintf("SMTP VRFY %s@%s from %s — 252 Cannot VRFY user, but will accept message for delivery", user, domain, req.AttackerIP)
			dev := targetDev
			if dev == nil {
				dev = fw
			}
			ev := sendSyslog(dev, msg, 5)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
			time.Sleep(20 * time.Millisecond)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 25, Protocol: 6, Bytes: 1600, Packets: 16, StartTime: time.Now(), EndTime: time.Now().Add(5 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		attackerDev, _ := getDeviceByIP(req.AttackerIP)
		if attackerDev == nil || targetDev == nil {
			logWarn("runSMTPUserEnum target=%s: no device with MAC address available, skipping PCAP", targetIP)
			continue
		}

		var frames [][]byte

		attackerdomain := fmt.Sprintf("mail.%s", domain)
		srcMAC := parseMACAddress(attackerDev.MACAddress)
		dstMAC := parseMACAddress(targetDev.MACAddress)
		src_port := randomPort()
		dst_port := uint16(587)

		clientSeq := rand.Uint32()
		serverSeq := uint32(0)

		// SYN
		frames = append(frames, create_TCP_frame(src_port, dst_port, 0x02, clientSeq, 0, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))
		clientSeq++
		// SYN-ACK
		frames = append(frames, create_TCP_frame(dst_port, src_port, 0x12, serverSeq, clientSeq, targetIP, req.AttackerIP, dstMAC, srcMAC, nil))
		serverSeq++
		// ACK
		frames = append(frames, create_TCP_frame(src_port, dst_port, 0x10, clientSeq, serverSeq, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))

		// 1. SMTP Server Banner
		banner := serverBanner(attackerdomain)
		frames = append(frames, create_TCP_frame(dst_port, src_port, 0x18, serverSeq, clientSeq, targetIP, req.AttackerIP, dstMAC, srcMAC, banner))
		serverSeq += uint32(len(banner))
		frames = append(frames, create_TCP_frame(src_port, dst_port, 0x10, clientSeq, serverSeq, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))

		// 2. Client EHLO
		ehlo := clientEhlo(fmt.Sprintf("attacker@%s", domain))
		frames = append(frames, create_TCP_frame(src_port, dst_port, 0x18, clientSeq, serverSeq, req.AttackerIP, targetIP, srcMAC, dstMAC, ehlo))
		clientSeq += uint32(len(ehlo))
		frames = append(frames, create_TCP_frame(dst_port, src_port, 0x10, serverSeq, clientSeq, targetIP, req.AttackerIP, dstMAC, srcMAC, nil))

		// 3. Server replies to EHLO
		ehloResp := serverEhloResponse(attackerdomain)
		frames = append(frames, create_TCP_frame(dst_port, src_port, 0x18, serverSeq, clientSeq, targetIP, req.AttackerIP, dstMAC, srcMAC, ehloResp))
		serverSeq += uint32(len(ehloResp))
		frames = append(frames, create_TCP_frame(src_port, dst_port, 0x10, clientSeq, serverSeq, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))

		// 4. VRFY for each candidate user
		for _, user := range users {
			mail_id := fmt.Sprintf("%s@%s", user, domain)
			vrfy := clientVrfy(user)
			frames = append(frames, create_TCP_frame(src_port, dst_port, 0x18, clientSeq, serverSeq, req.AttackerIP, targetIP, srcMAC, dstMAC, vrfy))
			clientSeq += uint32(len(vrfy))
			frames = append(frames, create_TCP_frame(dst_port, src_port, 0x10, serverSeq, clientSeq, targetIP, req.AttackerIP, dstMAC, srcMAC, nil))

			resp := serverEhloResponse(mail_id)
			frames = append(frames, create_TCP_frame(dst_port, src_port, 0x18, serverSeq, clientSeq, targetIP, req.AttackerIP, dstMAC, srcMAC, resp))
			serverSeq += uint32(len(resp))
			frames = append(frames, create_TCP_frame(src_port, dst_port, 0x10, clientSeq, serverSeq, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))
		}

		// Connection teardown
		frames = append(frames, create_TCP_frame(src_port, dst_port, 0x01, clientSeq, serverSeq, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))
		clientSeq++
		frames = append(frames, create_TCP_frame(dst_port, src_port, 0x10, serverSeq, clientSeq, targetIP, req.AttackerIP, dstMAC, srcMAC, nil))
		frames = append(frames, create_TCP_frame(dst_port, src_port, 0x01, serverSeq, clientSeq, targetIP, req.AttackerIP, dstMAC, srcMAC, nil))
		serverSeq++
		frames = append(frames, create_TCP_frame(src_port, dst_port, 0x10, clientSeq, serverSeq, req.AttackerIP, targetIP, srcMAC, dstMAC, nil))

		path, _ := writePCAPFile(req.RunID, "smtp_user_enum", frames, defaultDuration)
		if path != "" {
			result.PCAPFiles = append(result.PCAPFiles, path)
		}
	}
	logInfo("Return from runSMTPUserEnum syslogs=%d", result.SyslogCount)
	return result, nil
}

func runWebDirBrute(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runWebDirBrute attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := getAttackParamInt(req.Params, "target_port", 80)
	fw := getFirewall()
	// path → HTTP status the simulated server returns. A real dir brute-force
	// is only useful when some paths are "found" (200/403/301) among the 404s.
	paths := []struct {
		path   string
		status int
	}{
		{"/admin", 403},
		{"/backup", 200},
		{"/.git", 200},
		{"/wp-admin", 301},
		{"/phpmyadmin", 403},
		{"/api/v1", 200},
		{"/swagger", 200},
		{"/actuator", 403},
		{"/.env", 200},
		{"/config", 404},
	}
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		for _, p := range paths {
			msg := fmt.Sprintf("%s - - \"GET %s HTTP/1.1\" %d 0 \"-\" \"gobuster/3.1.0\"", req.AttackerIP, p.path, p.status)
			dev := targetDev
			if dev == nil {
				dev = fw
			}
			ev := sendSyslog(dev, msg, 6)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: uint16(targetPort), Protocol: 6, Bytes: uint32(len(paths) * 300), Packets: uint32(len(paths) * 3), StartTime: time.Now(), EndTime: time.Now().Add(10 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		wdbPath, wdbErr := PCAPGenericTCPExchange(req.RunID, "web_dir_brute", req.AttackerIP, targetIP, uint16(targetPort),
			[]byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: gobuster/3.1.0\r\n\r\n", paths[0].path, targetIP)),
			[]byte(fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", paths[0].status)))
		if wdbErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, wdbPath)
		}
	}
	logInfo("Return from runWebDirBrute syslogs=%d", result.SyslogCount)
	return result, nil
}

func runLDAPEnum(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runLDAPEnum attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	baseDN := getAttackParam(req.Params, "base_dn", "dc=corp,dc=local")
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		targetDev, _ := getDeviceByIP(targetIP)
		msgs := []string{
			fmt.Sprintf("LDAP anonymous bind from %s to %s accepted", req.AttackerIP, targetIP),
			fmt.Sprintf("LDAP search from %s: base='%s' filter='(objectClass=user)' — 142 objects returned", req.AttackerIP, baseDN),
			fmt.Sprintf("LDAP search from %s: base='%s' filter='(objectClass=group)' — 18 groups returned", req.AttackerIP, baseDN),
			fmt.Sprintf("LDAP search from %s: filter='(userAccountControl:1.2.840.113556.1.4.803:=65536)' — 3 never-expire accounts", req.AttackerIP),
		}
		dev := targetDev
		if dev == nil {
			dev = fw
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 389, Protocol: 6, Bytes: 45000, Packets: 80, StartTime: time.Now(), EndTime: time.Now().Add(8 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		ldapPath, ldapErr := PCAPGenericTCPExchange(req.RunID, "ldap_enum", req.AttackerIP, targetIP, 389,
			[]byte(fmt.Sprintf("searchRequest base=%s filter=(objectClass=user)", baseDN)), nil)
		if ldapErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, ldapPath)
		}
	}
	logInfo("Return from runLDAPEnum syslogs=%d", result.SyslogCount)
	return result, nil
}

func runNetBIOSEnum(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runNetBIOSEnum attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if d, ok := getDeviceByIP(targetIP); ok && d != nil {
			dev = d
		}
		msgs := []string{
			fmt.Sprintf("NetBIOS name query from %s: NBSTAT * to %s — workgroup CORP", req.AttackerIP, targetIP),
			fmt.Sprintf("NetBIOS: %s reports name WINSERVER01<00> (workstation) CORP<00> (domain)", targetIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 6)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 137, Protocol: 17, Bytes: 500, Packets: 4, StartTime: time.Now(), EndTime: time.Now().Add(time.Second)},
			{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 138, Protocol: 17, Bytes: 300, Packets: 2, StartTime: time.Now(), EndTime: time.Now().Add(time.Second)},
		}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "UDP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		if attackerDev, ok := getDeviceByIP(req.AttackerIP); ok && attackerDev != nil {
			if devMAC, ok2 := getDeviceByIP(targetIP); ok2 && devMAC != nil {
				srcMAC := parseMACAddress(attackerDev.MACAddress)
				dstMAC := parseMACAddress(devMAC.MACAddress)
				srcPort := randomPort()
				query := buildUDPDatagram(srcPort, 137, NBNS_Name_Query_Request)
				queryFrame := buildEthernetFrame(srcMAC, dstMAC, buildIPv4Packet(req.AttackerIP, targetIP, 17, query))
				response := buildUDPDatagram(137, srcPort, Get_NBNS_Response(targetIP))
				responseFrame := buildEthernetFrame(dstMAC, srcMAC, buildIPv4Packet(targetIP, req.AttackerIP, 17, response))
				nbPath, _ := writePCAPFile(req.RunID, "netbios_enum", [][]byte{queryFrame, responseFrame}, defaultDuration)
				if nbPath != "" {
					result.PCAPFiles = append(result.PCAPFiles, nbPath)
				}
			}
		}
	}
	logInfo("Return from runNetBIOSEnum syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSSLScan(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSSLScan attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetPort := getAttackParamInt(req.Params, "target_port", 443)
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		msgs := []string{
			fmt.Sprintf("TLS ClientHello from %s to %s:%d — SSLv3 offered (POODLE probe)", req.AttackerIP, targetIP, targetPort),
			fmt.Sprintf("TLS ClientHello from %s — TLS_RSA_WITH_RC4_128_MD5 offered (weak cipher probe)", req.AttackerIP),
			fmt.Sprintf("Certificate SAN enumeration from %s: subject=*.corp.local — SANs: vpn.corp.local, mail.corp.local, dc01.corp.local", req.AttackerIP),
		}
		dev := fw
		if fw == nil {
			dev, _ = getDeviceByIP(targetIP)
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 5)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, targetIP, "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: uint16(targetPort), Protocol: 6, Bytes: 6000, Packets: 20, StartTime: time.Now(), EndTime: time.Now().Add(4 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		sslScanPath, sslScanErr := PCAPGenericTCPExchange(req.RunID, "ssl_scan", req.AttackerIP, targetIP, uint16(targetPort), buildMinimalTLSClientHello(), nil)
		if sslScanErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, sslScanPath)
		}
	}
	logInfo("Return from runSSLScan syslogs=%d", result.SyslogCount)
	return result, nil
}

func runCloudMetaDiscovery(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runCloudMetaDiscovery attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	fw := getFirewall()
	for _, targetIP := range req.TargetIPs {
		dev := fw
		if fw == nil {
			dev, _ = getDeviceByIP(targetIP)
		}
		msgs := []string{
			fmt.Sprintf("%s - - \"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\" 200 — SSRF to cloud metadata", req.AttackerIP),
			fmt.Sprintf("%s - - \"GET http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1\" 200 — IAM role credentials exposed", req.AttackerIP),
			fmt.Sprintf("WAF alert: SSRF attempt from %s targeting metadata endpoint 169.254.169.254", req.AttackerIP),
		}
		for _, msg := range msgs {
			ev := sendSyslog(dev, msg, 3)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetIP, req.AttackerIP, "169.254.169.254", "TCP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: "169.254.169.254", SrcPort: randomPort(), DstPort: 80, Protocol: 6, Bytes: 4000, Packets: 8, StartTime: time.Now(), EndTime: time.Now().Add(2 * time.Second), TCPFlags: 0x18}}
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, "169.254.169.254", "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
		ssrfPath, ssrfErr := PCAPGenericTCPExchange(req.RunID, "cloud_meta_discovery", req.AttackerIP, "169.254.169.254", 80,
			[]byte("GET /latest/meta-data/iam/security-credentials/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"),
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		if ssrfErr == nil {
			result.PCAPFiles = append(result.PCAPFiles, ssrfPath)
		}
	}
	logInfo("Return from runCloudMetaDiscovery syslogs=%d", result.SyslogCount)
	return result, nil
}

func runSubdomainEnum(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runSubdomainEnum attacker=%s", req.AttackerIP)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	domain := getAttackParam(req.Params, "domain", "corp.local")
	count := getAttackParamInt(req.Params, "count", 200)
	dnsDev := getDNSServer()
	if dnsDev == nil {
		return result, nil
	}
	subdomains := []string{"mail", "vpn", "dev", "stage", "prod", "api", "git", "admin", "portal", "intranet", "owa", "remote", "secure", "dc01", "dc02"}
	queriesSent := 0
	for idx := 0; idx < count; idx++ {
		sub := subdomains[idx%len(subdomains)]
		msg := fmt.Sprintf("client %s#%d: query: %s.%s IN A +", req.AttackerIP, randomPort(), sub, domain)
		ev := sendSyslog(dnsDev, msg, 6)
		result.SyslogCount++
		queriesSent++
		eventID, _ := recordRunEvent(req.RunID, "syslog", dnsDev.Name, req.AttackerIP, dnsDev.IPAddress, "UDP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
		time.Sleep(10 * time.Millisecond)
	}
	flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: dnsDev.IPAddress, SrcPort: randomPort(), DstPort: 53, Protocol: 17, Bytes: uint32(queriesSent * 60), Packets: uint32(queriesSent * 2), StartTime: time.Now(), EndTime: time.Now().Add(time.Duration(queriesSent/10) * time.Second)}}
	fw := getFirewall()
	if fw != nil && fw.Telemetry.Netflow {
		ExportNetflowV9(fw.IPAddress, flows)
	}
	result.FlowCount++
	flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, dnsDev.IPAddress, "UDP", flows)
	result.EventIDs = append(result.EventIDs, flowID)
	dnsPath, dnsErr := PCAPDNSQueryResponse(req.RunID, "subdomain_enum", req.AttackerIP, dnsDev.IPAddress, fmt.Sprintf("%s.%s", subdomains[0], domain), true)
	if dnsErr == nil {
		result.PCAPFiles = append(result.PCAPFiles, dnsPath)
	}
	logInfo("Return from runSubdomainEnum syslogs=%d", result.SyslogCount)
	return result, nil
}
