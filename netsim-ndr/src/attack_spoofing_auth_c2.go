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
	switches := getRouters()

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
	logInfo("Return from runARPSpoofing syslogs=%d", result.SyslogCount)
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
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", spoofIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)
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
	return result, nil
}

func runMACSpoofing(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering runMACSpoofing attacker=%s", req.AttackerIP)

	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	targetMAC := getAttackParam(req.Params, "target_mac", "00:11:22:33:44:05")

	for _, swDev := range getRouters() {
		if swDev.DeviceType != "switch" {
			continue
		}
		msg := fmt.Sprintf("MAC address %s has moved from port Gi0/1 to port Gi0/5 — possible MAC spoofing", targetMAC)
		ev := sendSyslog(swDev, msg, 3)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", swDev.Name, req.AttackerIP, "broadcast", "ETH", ev)
		result.EventIDs = append(result.EventIDs, eventID)
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
		msg := fmt.Sprintf("%s - - \"GET /search?q=<script>document.location='http://attacker/%s'</script> HTTP/1.1\" 200 1234",
			req.AttackerIP, randomHexString(8))
		ev := sendSyslog(targetDev, msg, 4)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "TCP", ev)
		result.EventIDs = append(result.EventIDs, eventID)
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

		flows := []FlowRecord{{SrcIP: req.AttackerIP, DstIP: targetIP, SrcPort: randomPort(), DstPort: 22, Protocol: 6, Bytes: 40000, Packets: 200, StartTime: time.Now().Add(-60 * time.Second), EndTime: time.Now()}}
		fw := getFirewall()
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 22, "ssh", 10)
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

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 3389, "rdp", 10)
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

		// PCAP (Option B)
		path, _ := PCAPBruteForce(req.RunID, req.AttackerIP, targetIP, 445, "smb", 10)
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
		for idx := 0; idx < min(listSize, 20); idx++ {
			user := fmt.Sprintf("user%d@corp.local", rand.Intn(1000))
			msg := fmt.Sprintf("Authentication failed for %s from %s — invalid credentials (credential stuffing suspected)", user, req.AttackerIP)
			ev := sendSyslog(targetDev, msg, 4)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", targetDev.Name, req.AttackerIP, targetIP, "HTTPS", ev)
			result.EventIDs = append(result.EventIDs, eventID)
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

		lateralFlows := FlowLateral(req.AttackerIP, targetIP)
		fw := getFirewall()
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, lateralFlows)
		}
		result.FlowCount += len(lateralFlows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", lateralFlows)
		result.EventIDs = append(result.EventIDs, flowID)
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
		result.FlowCount += len(beaconFlows)
		fw := getFirewall()
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, beaconFlows)
		}
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", infectedIP, c2Dev.IPAddress, "HTTPS", beaconFlows)
		result.EventIDs = append(result.EventIDs, flowID)

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
			eventID, _ := recordRunEvent(req.RunID, "syslog", "dns-server", infectedIP, dnsDev.IPAddress, "UDP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
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
		for idx := 0; idx < count; idx++ {
			encodedData := randomHexString(64)
			msg := fmt.Sprintf("Outbound HTTP: src=%s dst=%s header X-Custom-Data: %s", infectedIP, c2Dev.IPAddress, encodedData)
			ev := sendSyslog(fw, msg, 6)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", "fw-perimeter", infectedIP, c2Dev.IPAddress, "HTTP", ev)
			result.EventIDs = append(result.EventIDs, eventID)
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
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, flows)
		}
		result.FlowCount += len(flows)
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", req.AttackerIP, targetIP, "TCP", flows)
		result.EventIDs = append(result.EventIDs, flowID)

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
	}
	return result, nil
}

func runExfilHTTP(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	dataMB := getAttackParamInt(req.Params, "data_mb", 100)
	c2Dev := getCCServer()

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
		if fw != nil && fw.Telemetry.Netflow {
			ExportNetflowV9(fw.IPAddress, exfilFlows)
		}
		result.FlowCount++
		flowID, _ := recordRunEvent(req.RunID, "netflow", "fw-perimeter", sourceIP, c2Dev.IPAddress, "HTTPS", exfilFlows)
		result.EventIDs = append(result.EventIDs, flowID)

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
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	ssid := getAttackParam(req.Params, "ssid", "Corp-WiFi")

	for _, apDev := range getWirelessAPs() {
		msg := fmt.Sprintf("Rogue AP detected: SSID '%s' MAC 00:aa:bb:cc:dd:ff RSSI -65dBm on channel 6 — evil twin suspected", ssid)
		ev := sendSyslog(apDev, msg, 2)
		result.SyslogCount++
		eventID, _ := recordRunEvent(req.RunID, "syslog", apDev.Name, req.AttackerIP, apDev.IPAddress, "802.11", ev)
		result.EventIDs = append(result.EventIDs, eventID)
	}
	return result, nil
}

func runDeauth(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	result := &AttackResult{AttackID: req.AttackID, RunID: req.RunID, AttackerIP: req.AttackerIP, TargetIPs: req.TargetIPs, StartedAt: time.Now()}
	apName := getAttackParam(req.Params, "ap_name", "ap-floor1")

	for _, apDev := range getWirelessAPs() {
		if apDev.Name != apName && apName != "" {
			continue
		}
		for idx := 0; idx < 10; idx++ {
			clientMAC := fmt.Sprintf("aa:bb:cc:%02x:%02x:%02x", rand.Intn(256), rand.Intn(256), rand.Intn(256))
			msg := fmt.Sprintf("Deauthentication flood: %d deauth frames from %s targeting client %s — denial of service",
				100+rand.Intn(400), req.AttackerIP, clientMAC)
			ev := sendSyslog(apDev, msg, 2)
			result.SyslogCount++
			eventID, _ := recordRunEvent(req.RunID, "syslog", apDev.Name, req.AttackerIP, apDev.IPAddress, "802.11", ev)
			result.EventIDs = append(result.EventIDs, eventID)
		}
		break
	}
	return result, nil
}
