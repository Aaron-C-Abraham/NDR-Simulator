// Package main — syslog_emitter.go
// Generates vendor-realistic syslog messages (RFC 3164 / RFC 5424 / CEF / LEEF)
// and delivers them via UDP to the NDR sensor.
package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// SyslogEvent is a single syslog message ready for transmission.
type SyslogEvent struct {
	DeviceIP   string    `json:"device_ip"`
	DeviceName string    `json:"device_name"`
	Facility   int       `json:"facility"`
	Severity   int       `json:"severity"`
	Timestamp  time.Time `json:"timestamp"`
	Message    string    `json:"message"`
	Format     string    `json:"format"` // rfc3164, rfc5424, cef, leef
	Raw        string    `json:"raw"`
}

// GlobalSyslogConn is the shared UDP connection to the syslog target.
var GlobalSyslogConn net.Conn

// initSyslogEmitter opens the UDP connection to the NDR syslog listener.
func initSyslogEmitter() error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering initSyslogEmitter")

	host := configString("ndr.syslog.host", "127.0.0.1")
	port := configInt("ndr.syslog.port", 514)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := net.Dial("udp", addr)
	if err != nil {
		logError("initSyslogEmitter dial %s: %v", addr, err)
		return err
	}
	GlobalSyslogConn = conn
	logInfo("Return from initSyslogEmitter target=%s", addr)
	return nil
}

// sendSyslog formats and transmits a syslog message based on the device vendor.
func sendSyslog(dev *Device, message string, severity int) *SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering sendSyslog device=%s msg=%s", dev.Name, message[:min(len(message), 80)])

	event := buildSyslogEvent(dev, message, severity)
	transmitSyslog(event)

	logTrace("sendSyslog format=%s raw=%s", event.Format, event.Raw[:min(len(event.Raw), 120)])
	logInfo("Return from sendSyslog device=%s", dev.Name)
	return event
}

// buildSyslogEvent selects the correct syslog format for the device vendor.
// Cisco is special-cased further by OSType/DeviceType: IOS routers/switches
// and AireOS wireless controllers emit genuinely different message styles in
// the real world even though both ship under the same vendor name.
func buildSyslogEvent(dev *Device, message string, severity int) *SyslogEvent {
	event := &SyslogEvent{
		DeviceIP:   dev.IPAddress,
		DeviceName: dev.Name,
		Facility:   23, // local7
		Severity:   severity,
		Timestamp:  time.Now(),
		Message:    message,
	}

	switch strings.ToLower(dev.Vendor) {
	case "fortinet":
		event.Format = "cef"
		event.Raw = buildFortinetCEF(dev, message, severity)
	case "cisco":
		if dev.DeviceType == "wireless_ap" || strings.Contains(strings.ToLower(dev.OSType), "aireos") {
			event.Format = "rfc3164"
			event.Raw = buildCiscoAireOS(dev, message, severity)
		} else {
			event.Format = "rfc3164"
			event.Raw = buildCiscoRFC3164(dev, message, severity)
		}
	case "arista":
		event.Format = "rfc5424"
		event.Raw = buildAristaRFC5424(dev, message, severity)
	case "microsoft":
		event.Format = "leef"
		event.Raw = buildWindowsLEEF(dev, message, severity)
	case "canonical", "red hat":
		event.Format = "rfc5424"
		event.Raw = buildLinuxRFC5424(dev, message, severity)
	case "apple":
		event.Format = "rfc5424"
		event.Raw = buildMacOSRFC5424(dev, message, severity)
	case "hikvision", "honeywell":
		event.Format = "rfc3164"
		event.Raw = buildIoTMinimal(dev, message, severity)
	default:
		event.Format = "rfc3164"
		event.Raw = buildGenericRFC3164(dev, message, severity)
	}
	return event
}

// transmitSyslog sends the raw syslog message over UDP.
func transmitSyslog(event *SyslogEvent) {
	storeSyslogMessage(event)
	broadcastEvent("syslog_received", map[string]interface{}{
		"device_ip":   event.DeviceIP,
		"device_name": event.DeviceName,
		"format":      event.Format,
		"severity":    event.Severity,
		"message":     event.Message,
		"raw":         event.Raw,
		"created_at":  event.Timestamp,
	})
	if GlobalSyslogConn == nil {
		return
	}
	_, err := fmt.Fprint(GlobalSyslogConn, event.Raw)
	if err != nil {
		logError("transmitSyslog write: %v", err)
	}
}

// rfc3164Timestamp formats the current time per RFC 3164 §4.1.2: "Mmm dd hh:mm:ss".
// The day-of-month MUST be space-padded (not zero-padded) for single digits —
// Go's "_2" layout verb does exactly that, where plain "02" would zero-pad.
func rfc3164Timestamp() string {
	return time.Now().Format("Jan _2 15:04:05")
}

// rfc5424Timestamp formats the current time per RFC 5424 §6.2.3. TIME-SECFRAC
// is capped at 6 digits by the spec, so we use a fixed 6-digit (microsecond)
// fraction rather than time.RFC3339Nano, which can emit up to 9 and produce
// an invalid timestamp.
func rfc5424Timestamp() string {
	return time.Now().Format("2006-01-02T15:04:05.000000Z07:00")
}

// buildFortinetCEF creates a Fortinet FortiOS CEF-format syslog message.
func buildFortinetCEF(dev *Device, message string, severity int) string {
	pri := dev.DeviceFacility()*8 + severity
	ts := rfc3164Timestamp()
	hostname := dev.Name
	sigID := fortinetSignatureID(message)
	devSev := mapSeverityCEF(severity)
	return fmt.Sprintf("<%d>%s %s CEF:0|Fortinet|FortiGate|7.4.0|%s|%s|%d|src=%s dst=%s msg=%s",
		pri, ts, hostname, sigID, message, devSev, dev.IPAddress, randomExternalIP(), message)
}

// fortinetSignatureID derives a stable per-event-type CEF Signature ID from
// the message text. Real FortiGate logs key each log line to a fixed
// subtype/logid so a SIEM can group event types; reusing the dynamic message
// text as the ID (the previous behavior) would give every single log line
// its own unique "type", which defeats that grouping.
func fortinetSignatureID(message string) string {
	msg := strings.ToLower(message)
	switch {
	case strings.Contains(msg, "syn") || strings.Contains(msg, "scan"):
		return "0419" // recon / port-scan
	case strings.Contains(msg, "denied"):
		return "0421" // policy deny
	case strings.Contains(msg, "outbound") || strings.Contains(msg, "bytes="):
		return "0431" // traffic / volume
	default:
		return "traffic"
	}
}

// buildCiscoRFC3164 creates a Cisco IOS/NX-OS RFC 3164 syslog message.
func buildCiscoRFC3164(dev *Device, message string, severity int) string {
	pri := dev.DeviceFacility()*8 + severity
	ts := rfc3164Timestamp()
	hostname := strings.ReplaceAll(dev.Name, "-", "")
	seqNo := rand.Intn(999999)
	return fmt.Sprintf("<%d>%s %s %%CISCO-6-SYSLOG: %06d: %%SYS-%d-MSG: %s",
		pri, ts, hostname, seqNo, severity, message)
}

// buildCiscoAireOS creates a Cisco WLC (AireOS) syslog message. AireOS gear
// is a different real-world product family from IOS — its log lines are
// prefixed with an internal task name instead of a hostname, carry
// millisecond-precision timestamps, and use wireless-specific mnemonics
// (DOT11/CAPWAP/APF) rather than IOS's %SYS family.
func buildCiscoAireOS(dev *Device, message string, severity int) string {
	pri := dev.DeviceFacility()*8 + severity
	ts := time.Now().Format("Jan _2 15:04:05.000")
	task := aireOSTask()
	mnemonic := aireOSMnemonic(message)
	return fmt.Sprintf("<%d>*%s: %s: %%%s: %s", pri, task, ts, mnemonic, message)
}

// aireOSTask returns a plausible internal AireOS task name.
func aireOSTask() string {
	tasks := []string{"spamApTask1", "spamApTask2", "spamApTask3", "spamApTask4", "dot1xMsgTask", "apf_rogue.c"}
	return tasks[rand.Intn(len(tasks))]
}

// aireOSMnemonic maps a message to a realistic AireOS facility-mnemonic.
func aireOSMnemonic(message string) string {
	msg := strings.ToLower(message)
	switch {
	case strings.Contains(msg, "rogue"):
		return "APF-1-ROGUE_AP_DETECTED"
	case strings.Contains(msg, "deauth") || strings.Contains(msg, "assoc"):
		return "DOT11-4-ASSOC_FAILED"
	case strings.Contains(msg, "capwap") || strings.Contains(msg, "tunnel"):
		return "CAPWAP-3-ERRORLOG"
	default:
		return "DOT11-4-CLIENT_LINK_REACHED_MAX_RETRIES"
	}
}

// buildAristaRFC5424 creates an Arista EOS RFC 5424 syslog message.
func buildAristaRFC5424(dev *Device, message string, severity int) string {
	pri := dev.DeviceFacility()*8 + severity
	ts := rfc5424Timestamp()
	hostname := dev.Name
	msgID := fmt.Sprintf("ID%04d", rand.Intn(9999))
	return fmt.Sprintf("<%d>1 %s %s Arista - %s - %s",
		pri, ts, hostname, msgID, message)
}

// buildWindowsLEEF creates a Windows/AD LEEF-format syslog message.
func buildWindowsLEEF(dev *Device, message string, severity int) string {
	pri := dev.DeviceFacility()*8 + severity
	ts := rfc3164Timestamp()
	hostname := dev.Name
	eventID := windowsEventID(message)
	return fmt.Sprintf("<%d>%s %s LEEF:2.0|Microsoft|Windows|2022|%d|devTime=%s\tsrc=%s\tmsg=%s",
		pri, ts, hostname, eventID, time.Now().Format("2006-01-02T15:04:05Z"), dev.IPAddress, message)
}

// buildLinuxRFC5424 creates a Linux syslog (journald/syslog) RFC 5424 message.
func buildLinuxRFC5424(dev *Device, message string, severity int) string {
	pri := dev.DeviceFacility()*8 + severity
	ts := rfc5424Timestamp()
	hostname := dev.Name
	appName := linuxAppName(message)
	pid := rand.Intn(65535)
	return fmt.Sprintf("<%d>1 %s %s %s %d - - %s",
		pri, ts, hostname, appName, pid, message)
}

// buildMacOSRFC5424 creates a macOS unified log RFC 5424 message.
func buildMacOSRFC5424(dev *Device, message string, severity int) string {
	pri := dev.DeviceFacility()*8 + severity
	ts := rfc5424Timestamp()
	return fmt.Sprintf("<%d>1 %s %s com.apple.securityd - - - %s",
		pri, ts, dev.Name, message)
}

// buildIoTMinimal creates a terse, minimally-structured syslog message
// typical of cheap embedded/IoT devices (camera DVRs, HVAC controllers),
// which generally implement just enough syslog to be functional and rarely
// bother with RFC 5424 structure.
func buildIoTMinimal(dev *Device, message string, severity int) string {
	pri := dev.DeviceFacility()*8 + severity
	ts := rfc3164Timestamp()
	return fmt.Sprintf("<%d>%s %s: %s", pri, ts, dev.Name, message)
}

// buildGenericRFC3164 creates a generic RFC 3164 syslog message.
func buildGenericRFC3164(dev *Device, message string, severity int) string {
	pri := 23*8 + severity
	ts := rfc3164Timestamp()
	return fmt.Sprintf("<%d>%s %s syslog: %s", pri, ts, dev.Name, message)
}

// DeviceFacility returns the syslog facility number for a device type.
func (dev *Device) DeviceFacility() int {
	switch dev.DeviceType {
	case "router", "firewall":
		return 23 // local7
	case "switch":
		return 22 // local6
	case "server", "workstation":
		return 1 // user
	case "iot":
		return 16 // local0 — typical dumping ground for embedded gear
	default:
		return 23
	}
}

// mapSeverityCEF maps syslog severity to CEF severity (0–10).
func mapSeverityCEF(severity int) int {
	switch severity {
	case 0, 1, 2:
		return 10
	case 3:
		return 8
	case 4:
		return 6
	case 5:
		return 4
	default:
		return 2
	}
}

// windowsEventID maps a message context to a realistic Windows Event ID.
func windowsEventID(message string) int {
	msg := strings.ToLower(message)
	switch {
	case strings.Contains(msg, "logon") || strings.Contains(msg, "login"):
		return 4624
	case strings.Contains(msg, "failed") && strings.Contains(msg, "logon"):
		return 4625
	case strings.Contains(msg, "logoff"):
		return 4634
	case strings.Contains(msg, "kerberos"):
		return 4768
	case strings.Contains(msg, "process"):
		return 4688
	case strings.Contains(msg, "network"):
		return 5156
	case strings.Contains(msg, "share"):
		return 5140
	default:
		return 4648
	}
}

// linuxAppName maps a message to a typical Linux daemon name.
func linuxAppName(message string) string {
	msg := strings.ToLower(message)
	switch {
	case strings.Contains(msg, "ssh"):
		return "sshd"
	case strings.Contains(msg, "dns") || strings.Contains(msg, "bind"):
		return "named"
	case strings.Contains(msg, "http") || strings.Contains(msg, "apache"):
		return "apache2"
	case strings.Contains(msg, "auth"):
		return "su"
	case strings.Contains(msg, "cron"):
		return "cron"
	default:
		return "kernel"
	}
}

// randomExternalIP returns a random external IP for simulated traffic.
func randomExternalIP() string {
	externalRanges := []string{
		"203.0.113.",
		"198.51.100.",
		"192.0.2.",
	}
	prefix := externalRanges[rand.Intn(len(externalRanges))]
	return fmt.Sprintf("%s%d", prefix, 1+rand.Intn(254))
}

// --- Pre-built syslog message templates for attack scenarios ---

// SyslogPortScan generates syslog messages for a port scan observed by the firewall.
func SyslogPortScan(attacker, target string, ports []uint16, port_mapping map[uint16]string, duration uint64) []SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering SyslogPortScan attacker=%s target=%s", attacker, target)
	fw := getFirewall()
	if fw == nil {
		return nil
	}

	var messages []string
	for _, port := range ports {
		switch port_mapping[port] {
		case "Open":
			msg := fmt.Sprintf("connection from %s to %s port %d TCP SYN ACCEPTED", attacker, target, port)
			messages = append(messages, msg)
		case "Close":
			msg := fmt.Sprintf("connection from %s to %s port %d TCP SYN DENIED", attacker, target, port)
			messages = append(messages, msg)
		}
	}

	var events []SyslogEvent
	for _, msg := range messages {
		if duration > 0 {
			sleepTime := time.Second / time.Duration(duration)
			time.Sleep(sleepTime) // simulate scan duration
		}
		ev := buildSyslogEvent(fw, msg, 4)
		transmitSyslog(ev)
		events = append(events, *ev)
	}
	logInfo("Return from SyslogPortScan events=%d", len(events))
	return events
}

// SyslogBruteForce generates authentication failure syslog messages.
func SyslogBruteForce(attacker, targetDevice *Device, service string) []SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering SyslogBruteForce attacker=%s target=%s service=%s", attacker.IPAddress, targetDevice.IPAddress, service)
	var events []SyslogEvent
	for i := 0; i < 20; i++ {
		var msg string
		user := pickRandomUsername()
		switch service {
		case "ssh":
			msg = fmt.Sprintf("Failed password for %s from %s port %d ssh2", user, attacker.IPAddress, randomPort())
		case "rdp":
			msg = fmt.Sprintf("An account failed to log on. Subject: %s Source Network Address: %s", user, attacker.IPAddress)
		case "smb":
			msg = fmt.Sprintf("Logon failure. User: %s Source: %s Status: 0xC000006D", user, attacker.IPAddress)
		default:
			msg = fmt.Sprintf("Authentication failure for user %s from %s", user, attacker.IPAddress)
		}
		ev := buildSyslogEvent(targetDevice, msg, 3)
		transmitSyslog(ev)
		events = append(events, *ev)
		time.Sleep(50 * time.Millisecond)
	}
	logInfo("Return from SyslogBruteForce events=%d", len(events))
	return events
}

// SyslogBeaconing generates periodic C2 beaconing syslog entries.
func SyslogBeaconing(infectedDevice *Device, c2IP string, interval time.Duration, count int) []SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering SyslogBeaconing device=%s c2=%s interval=%v count=%d", infectedDevice.Name, c2IP, interval, count)
	var events []SyslogEvent
	for i := 0; i < count; i++ {
		dstPort := uint16(443)
		msg := fmt.Sprintf("Outbound connection: src=%s dst=%s dstport=%d proto=TCP bytes=%d",
			infectedDevice.IPAddress, c2IP, dstPort, 200+rand.Intn(800))
		ev := buildSyslogEvent(getFirewall(), msg, 6)
		transmitSyslog(ev)
		events = append(events, *ev)
		time.Sleep(interval)
	}
	logInfo("Return from SyslogBeaconing events=%d", len(events))
	return events
}

// SyslogDNSTunnel generates DNS-based covert channel syslog entries.
func SyslogDNSTunnel(infectedDevice *Device, domain string, count int) []SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering SyslogDNSTunnel device=%s domain=%s count=%d", infectedDevice.Name, domain, count)
	dnsSrv := getDNSServer()
	if dnsSrv == nil {
		return nil
	}
	var events []SyslogEvent
	for i := 0; i < count; i++ {
		subdomain := fmt.Sprintf("%s.%s", randomHexString(32), domain)
		msg := fmt.Sprintf("client %s#%d: query: %s IN TXT + (%s)",
			infectedDevice.IPAddress, randomPort(), subdomain, dnsSrv.IPAddress)
		ev := buildSyslogEvent(dnsSrv, msg, 6)
		transmitSyslog(ev)
		events = append(events, *ev)
		time.Sleep(100 * time.Millisecond)
	}
	logInfo("Return from SyslogDNSTunnel events=%d", len(events))
	return events
}

// SyslogLateralMovement generates SMB/pass-the-hash lateral movement messages.
func SyslogLateralMovement(sourceDevice, targetDevice *Device) []SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering SyslogLateralMovement src=%s dst=%s", sourceDevice.IPAddress, targetDevice.IPAddress)
	var events []SyslogEvent

	// Source device — outbound
	msg1 := fmt.Sprintf("SMB connection to %s share \\\\%s\\C$ from %s", targetDevice.IPAddress, targetDevice.IPAddress, sourceDevice.IPAddress)
	ev1 := buildSyslogEvent(sourceDevice, msg1, 4)
	transmitSyslog(ev1)
	events = append(events, *ev1)

	// Target device — logon event
	msg2 := fmt.Sprintf("An account was successfully logged on. Subject AccountName: CORP\\Administrator Network Address: %s", sourceDevice.IPAddress)
	ev2 := buildSyslogEvent(targetDevice, msg2, 4)
	transmitSyslog(ev2)
	events = append(events, *ev2)

	// Firewall sees internal lateral traffic
	fw := getFirewall()
	if fw != nil {
		msg3 := fmt.Sprintf("allow src=%s dst=%s dstport=445 proto=TCP action=ACCEPT", sourceDevice.IPAddress, targetDevice.IPAddress)
		ev3 := buildSyslogEvent(fw, msg3, 6)
		transmitSyslog(ev3)
		events = append(events, *ev3)
	}
	logInfo("Return from SyslogLateralMovement events=%d", len(events))
	return events
}

// SyslogRansomware generates file encryption / ransomware activity syslog messages.
func SyslogRansomware(infectedDevice *Device) []SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering SyslogRansomware device=%s", infectedDevice.Name)
	var events []SyslogEvent
	extensions := []string{".docx", ".xlsx", ".pdf", ".png", ".jpg", ".db", ".bak"}
	for _, ext := range extensions {
		for idx := 0; idx < 5; idx++ {
			msg := fmt.Sprintf("File access denied: C:\\Users\\Finance\\Documents\\%s%s%d — access by unknown process",
				randomHexString(8), ext, idx)
			ev := buildSyslogEvent(infectedDevice, msg, 2)
			transmitSyslog(ev)
			events = append(events, *ev)
		}
	}
	logInfo("Return from SyslogRansomware events=%d", len(events))
	return events
}

// SyslogDataExfil generates large outbound transfer syslog messages.
func SyslogDataExfil(sourceDevice *Device, destIP string) []SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering SyslogDataExfil src=%s dst=%s", sourceDevice.IPAddress, destIP)
	var events []SyslogEvent
	fw := getFirewall()
	if fw == nil {
		return nil
	}
	for idx := 0; idx < 5; idx++ {
		bytes := 50000000 + rand.Intn(50000000)
		msg := fmt.Sprintf("outbound traffic: src=%s dst=%s dstport=443 proto=TCP bytes=%d duration=120s",
			sourceDevice.IPAddress, destIP, bytes)
		ev := buildSyslogEvent(fw, msg, 4)
		transmitSyslog(ev)
		events = append(events, *ev)
		time.Sleep(200 * time.Millisecond)
	}
	logInfo("Return from SyslogDataExfil events=%d", len(events))
	return events
}

// SyslogARPSpoofing generates ARP spoofing syslog messages from a switch.
func SyslogARPSpoofing(attackerIP, victimIP string, switchDev *Device) []SyslogEvent {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering SyslogARPSpoofing attacker=%s victim=%s switch=%s", attackerIP, victimIP, switchDev.Name)
	var events []SyslogEvent
	for idx := 0; idx < 5; idx++ {
		msg := fmt.Sprintf("ARP mismatch detected: IP %s claimed by MAC 00:aa:bb:cc:dd:01 (was 00:11:22:33:44:xx), ARP poisoning suspected",
			victimIP)
		ev := buildSyslogEvent(switchDev, msg, 3)
		transmitSyslog(ev)
		events = append(events, *ev)
	}
	logInfo("Return from SyslogARPSpoofing events=%d", len(events))
	return events
}

// pickRandomUsername returns a simulated username for brute-force messages.
func pickRandomUsername() string {
	names := []string{"admin", "administrator", "root", "user", "guest", "service", "sa", "oracle", "postgres"}
	return names[rand.Intn(len(names))]
}

// randomHexString generates a random hex string of given length.
func randomHexString(length int) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, length)
	for idx := range result {
		result[idx] = hexChars[rand.Intn(len(hexChars))]
	}
	return string(result)
}
