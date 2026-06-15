// Package main — attack_engine.go
// Central attack orchestration layer. Dispatches attack modules and
// records all generated telemetry events to the database.
package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AttackDefinition describes a single attack capability.
type AttackDefinition struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	MitreIDs    []string `json:"mitre_ids"`
	Description string   `json:"description"`
	Parameters  []AttackParam `json:"parameters"`
}

// AttackParam describes a configurable parameter for an attack.
type AttackParam struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // string, int, bool, ip, duration
	Default     string `json:"default"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// AttackRequest is the API request to launch an attack.
type AttackRequest struct {
	AttackID   string            `json:"attack_id"`
	RunID      string            `json:"run_id"`
	AttackerIP string            `json:"attacker_ip"`
	TargetIPs  []string          `json:"target_ips"`
	Params     map[string]string `json:"params"`
}

// AttackResult summarises what happened after an attack executes.
type AttackResult struct {
	AttackID       string        `json:"attack_id"`
	RunID          string        `json:"run_id"`
	AttackerIP     string        `json:"attacker_ip"`
	TargetIPs      []string      `json:"target_ips"`
	StartedAt      time.Time     `json:"started_at"`
	CompletedAt    time.Time     `json:"completed_at"`
	SyslogCount    int           `json:"syslog_count"`
	FlowCount      int           `json:"flow_count"`
	PCAPFiles      []string      `json:"pcap_files"`
	EventIDs       []int64       `json:"event_ids"`
	Error          string        `json:"error,omitempty"`
}

// GlobalActiveAttacks tracks currently running attack goroutines by runID.
var GlobalActiveAttacks = map[string]bool{}
var GlobalActiveAttacksLock sync.Mutex

// GlobalAttackRegistry is the catalog of all available attack modules.
var GlobalAttackRegistry []*AttackDefinition

// initAttackRegistry populates the catalog of 101 attacks.
func initAttackRegistry() {
	logInfo("Entering initAttackRegistry")
	GlobalAttackRegistry = buildAttackRegistry()
	logInfo("Return from initAttackRegistry attacks=%d", len(GlobalAttackRegistry))
}

// executeAttack dispatches the attack identified by req.AttackID.
func executeAttack(req AttackRequest) (*AttackResult, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering executeAttack attackID=%s runID=%s attacker=%s", req.AttackID, req.RunID, req.AttackerIP)

	result := &AttackResult{
		AttackID:   req.AttackID,
		RunID:      req.RunID,
		AttackerIP: req.AttackerIP,
		TargetIPs:  req.TargetIPs,
		StartedAt:  time.Now(),
	}

	if req.RunID == "" {
		req.RunID = uuid.New().String()
		result.RunID = req.RunID
	}
	
	var err error
	switch req.AttackID {
	case "recon-portscan":
		result, err = runPortScan(req)
	case "recon-os-fingerprint":
		result, err = runOSFingerprint(req)
	case "recon-service-enum":
		result, err = runServiceEnum(req)
	case "recon-dns-recon":
		result, err = runDNSRecon(req)
	case "recon-netdiscover":
		result, err = runNetDiscover(req)
	case "dos-syn-flood":
		result, err = runSYNFlood(req)
	case "dos-udp-flood":
		result, err = runUDPFlood(req)
	case "dos-icmp-flood":
		result, err = runICMPFlood(req)
	case "dos-http-flood":
		result, err = runHTTPFlood(req)
	case "dos-slowloris":
		result, err = runSlowloris(req)
	case "dos-amplification":
		result, err = runAmplification(req)
	case "spoof-arp":
		result, err = runARPSpoofing(req)
	case "spoof-ipsrc":
		result, err = runIPSourceSpoof(req)
	case "spoof-dns":
		result, err = runDNSSpoofing(req)
	case "spoof-mac":
		result, err = runMACSpoofing(req)
	case "inject-sql":
		result, err = runSQLInjection(req)
	case "inject-cmd":
		result, err = runCommandInjection(req)
	case "inject-xss":
		result, err = runXSSInjection(req)
	case "inject-ldap":
		result, err = runLDAPInjection(req)
	case "auth-bruteforce-ssh":
		result, err = runBruteForceSSH(req)
	case "auth-bruteforce-rdp":
		result, err = runBruteForceRDP(req)
	case "auth-bruteforce-smb":
		result, err = runBruteForceSMB(req)
	case "auth-credstuff":
		result, err = runCredentialStuffing(req)
	case "auth-kerberoasting":
		result, err = runKerberoasting(req)
	case "auth-passthehash":
		result, err = runPassTheHash(req)
	case "c2-beaconing":
		result, err = runC2Beaconing(req)
	case "c2-dga":
		result, err = runDGA(req)
	case "c2-dns-tunnel":
		result, err = runDNSTunnel(req)
	case "c2-http-covert":
		result, err = runHTTPCovertChannel(req)
	case "lateral-smb":
		result, err = runLateralSMB(req)
	case "lateral-psexec":
		result, err = runPsExec(req)
	case "exfil-http":
		result, err = runExfilHTTP(req)
	case "wireless-rogue-ap":
		result, err = runRogueAP(req)
	case "wireless-deauth":
		result, err = runDeauth(req)
	// ── Reconnaissance (extended) ──
	case "recon-snmp-enum":
		result, err = runSNMPEnum(req)
	case "recon-smtp-user":
		result, err = runSMTPUserEnum(req)
	case "recon-web-dir":
		result, err = runWebDirBrute(req)
	case "recon-ldap-enum":
		result, err = runLDAPEnum(req)
	case "recon-netbios":
		result, err = runNetBIOSEnum(req)
	case "recon-ssl-scan":
		result, err = runSSLScan(req)
	case "recon-cloud-meta":
		result, err = runCloudMetaDiscovery(req)
	case "recon-subdomain":
		result, err = runSubdomainEnum(req)
	// ── DoS/DDoS (extended) ──
	case "dos-http2-reset":
		result, err = runHTTP2Reset(req)
	case "dos-ssl-exhaust":
		result, err = runSSLExhaustion(req)
	case "dos-memcached-amp":
		result, err = runMemcachedAmp(req)
	case "dos-rudy":
		result, err = runRUDY(req)
	case "dos-ack-flood":
		result, err = runACKFlood(req)
	case "dos-rst-flood":
		result, err = runRSTFlood(req)
	// ── Spoofing (extended) ──
	case "spoof-dhcp-starve":
		result, err = runDHCPStarvation(req)
	case "spoof-dhcp-rogue":
		result, err = runRogueDHCP(req)
	case "spoof-vlan-hop":
		result, err = runVLANHopping(req)
	case "spoof-bgp-hijack":
		result, err = runBGPHijack(req)
	// ── Injection (extended) ──
	case "inject-xxe":
		result, err = runXXEInjection(req)
	case "inject-ssti":
		result, err = runSSTInjection(req)
	case "inject-lfi":
		result, err = runLFIAttack(req)
	case "inject-ssrf":
		result, err = runSSRFAttack(req)
	case "inject-nosql":
		result, err = runNoSQLInjection(req)
	case "inject-header":
		result, err = runHeaderInjection(req)
	// ── Authentication (extended) ──
	case "auth-bruteforce-ftp":
		result, err = runBruteForceFTP(req)
	case "auth-bruteforce-telnet":
		result, err = runBruteForceTelnet(req)
	case "auth-bruteforce-smtp":
		result, err = runBruteForceSMTP(req)
	case "auth-bruteforce-snmp":
		result, err = runBruteForceSNMP(req)
	case "auth-bruteforce-winrm":
		result, err = runBruteForceWinRM(req)
	case "auth-bruteforce-vnc":
		result, err = runBruteForceVNC(req)
	case "auth-passtheticket":
		result, err = runPassTheTicket(req)
	case "auth-asreproast":
		result, err = runASREPRoasting(req)
	// ── C2 (extended) ──
	case "c2-icmp-tunnel":
		result, err = runICMPTunnel(req)
	case "c2-smb-channel":
		result, err = runSMBChannel(req)
	case "c2-websocket":
		result, err = runWebSocketC2(req)
	case "c2-domain-front":
		result, err = runDomainFronting(req)
	case "c2-reverse-shell":
		result, err = runReverseShell(req)
	case "c2-powershell":
		result, err = runPowerShellC2(req)
	case "c2-exfil-dns":
		result, err = runDNSExfil(req)
	case "c2-exfil-icmp":
		result, err = runICMPExfil(req)
	// ── Lateral Movement (extended) ──
	case "lateral-wmi":
		result, err = runWMILateral(req)
	case "lateral-dcom":
		result, err = runDCOMLateral(req)
	case "lateral-rdp-hijack":
		result, err = runRDPHijack(req)
	case "exfil-ftp":
		result, err = runFTPExfil(req)
	case "exfil-smtp":
		result, err = runSMTPExfil(req)
	case "lateral-golden-ticket":
		result, err = runGoldenTicket(req)
	case "lateral-ssh-tunnel":
		result, err = runSSHTunnel(req)
	// ── Wireless (extended) ──
	case "wireless-pmkid":
		result, err = runPMKIDAttack(req)
	case "wireless-evil-twin":
		result, err = runEvilTwin(req)
	// ── Evasion ──
	case "evade-fragmentation":
		result, err = runIPFragmentation(req)
	case "evade-protocol-tunnel":
		result, err = runProtocolTunnel(req)
	case "evade-low-slow":
		result, err = runLowSlowScan(req)
	case "evade-decoy":
		result, err = runDecoyScan(req)
	default:
		err = fmt.Errorf("unknown attack ID: %s", req.AttackID)
	}

	if err != nil {
		result.Error = err.Error()
		logError("executeAttack %s: %v", req.AttackID, err)
	}
	result.CompletedAt = time.Now()
	writeAuditLog("simulator", "attack_executed", req.AttackID, result)
	logInfo("Return from executeAttack attackID=%s syslogs=%d flows=%d pcap=%d", req.AttackID, result.SyslogCount, result.FlowCount, len(result.PCAPFiles))
	return result, err
}

// recordRunEvent persists a telemetry event for a test run.
func recordRunEvent(runID, eventType, sourceDevice, srcIP, dstIP, protocol string, payload interface{}) (int64, error) {
	defer panicHandler(traceFunc(), nil)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		logError("recordRunEvent marshal: %v", err)
		payloadJSON = []byte("{}")
	}

	res, err := GlobalDB.Exec(`
		INSERT INTO run_events (run_id, event_time, event_type, source_device, source_ip, dest_ip, protocol, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		runID, time.Now().UTC().Format(time.RFC3339), eventType, sourceDevice, srcIP, dstIP, protocol, string(payloadJSON))
	if err != nil {
		logError("recordRunEvent exec: %v", err)
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// buildAttackRegistry returns the full catalog of 87 network-layer attack modules.
func buildAttackRegistry() []*AttackDefinition {
	return []*AttackDefinition{
		// ── Reconnaissance (13) ──
		{ID: "recon-portscan", Name: "Port Scan (nmap-style)", Category: "Reconnaissance", MitreIDs: []string{"T1046"}, Description: "TCP SYN scan across a range of ports to identify open services.", Parameters: []AttackParam{{Name: "port_range", Type: "string", Default: "1-1024", Description: "Port range to scan"}, {Name: "rate", Type: "int", Default: "1000", Description: "Packets per second"}}},
		{ID: "recon-os-fingerprint", Name: "OS Fingerprinting", Category: "Reconnaissance", MitreIDs: []string{"T1082"}, Description: "TCP/IP stack fingerprinting to determine target OS.", Parameters: []AttackParam{}},
		{ID: "recon-service-enum", Name: "Service Enumeration", Category: "Reconnaissance", MitreIDs: []string{"T1046", "T1135"}, Description: "Banner-grabbing and SMB/SNMP enumeration.", Parameters: []AttackParam{}},
		{ID: "recon-dns-recon", Name: "DNS Reconnaissance", Category: "Reconnaissance", MitreIDs: []string{"T1018"}, Description: "DNS zone transfer and PTR record enumeration.", Parameters: []AttackParam{{Name: "domain", Type: "string", Default: "corp.local", Description: "Target domain"}}},
		{ID: "recon-netdiscover", Name: "Network Discovery (ARP)", Category: "Reconnaissance", MitreIDs: []string{"T1018"}, Description: "ARP sweep to enumerate live hosts on the local subnet.", Parameters: []AttackParam{}},
		{ID: "recon-snmp-enum", Name: "SNMP Enumeration", Category: "Reconnaissance", MitreIDs: []string{"T1046"}, Description: "Query SNMP OIDs with default community strings to enumerate device config and routing tables.", Parameters: []AttackParam{{Name: "community", Type: "string", Default: "public", Description: "SNMP community string"}}},
		{ID: "recon-smtp-user", Name: "SMTP User Enumeration", Category: "Reconnaissance", MitreIDs: []string{"T1589.003"}, Description: "VRFY/EXPN/RCPT TO commands to enumerate valid mail accounts.", Parameters: []AttackParam{{Name: "domain", Type: "string", Default: "corp.local", Description: "Mail domain"}}},
		{ID: "recon-web-dir", Name: "Web Directory Brute Force", Category: "Reconnaissance", MitreIDs: []string{"T1595.003"}, Description: "Enumerate hidden paths and files via wordlist (Gobuster/dirbuster-style).", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "80", Description: "HTTP port"}, {Name: "wordcount", Type: "int", Default: "500", Description: "Words to try"}}},
		{ID: "recon-ldap-enum", Name: "LDAP Enumeration", Category: "Reconnaissance", MitreIDs: []string{"T1018"}, Description: "Anonymous LDAP bind to enumerate users, groups, and OUs.", Parameters: []AttackParam{{Name: "base_dn", Type: "string", Default: "dc=corp,dc=local", Description: "LDAP base DN"}}},
		{ID: "recon-netbios", Name: "NetBIOS/WINS Enumeration", Category: "Reconnaissance", MitreIDs: []string{"T1046"}, Description: "NetBIOS name queries and WINS lookups to map Windows workgroup.", Parameters: []AttackParam{}},
		{ID: "recon-ssl-scan", Name: "SSL/TLS Certificate Scan", Category: "Reconnaissance", MitreIDs: []string{"T1595.001"}, Description: "Enumerate TLS versions, cipher suites, and certificate SANs for intel.", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "443", Description: "TLS port"}}},
		{ID: "recon-cloud-meta", Name: "Cloud Metadata Discovery", Category: "Reconnaissance", MitreIDs: []string{"T1552.005"}, Description: "SSRF probe of cloud metadata endpoint (169.254.169.254) to retrieve IAM credentials.", Parameters: []AttackParam{}},
		{ID: "recon-subdomain", Name: "Subdomain Enumeration", Category: "Reconnaissance", MitreIDs: []string{"T1595.001"}, Description: "DNS brute-force subdomain discovery using a common wordlist.", Parameters: []AttackParam{{Name: "domain", Type: "string", Default: "corp.local"}, {Name: "count", Type: "int", Default: "200"}}},
		// ── DoS / DDoS (12) ──
		{ID: "dos-syn-flood", Name: "TCP SYN Flood", Category: "DoS/DDoS", MitreIDs: []string{"T1499"}, Description: "SYN flood targeting TCP listener to exhaust connection table.", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "443"}, {Name: "pps", Type: "int", Default: "10000"}, {Name: "duration", Type: "int", Default: "30"}}},
		{ID: "dos-udp-flood", Name: "UDP Flood", Category: "DoS/DDoS", MitreIDs: []string{"T1499"}, Description: "High-rate UDP packet flood.", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "53"}, {Name: "pps", Type: "int", Default: "50000"}}},
		{ID: "dos-icmp-flood", Name: "ICMP Ping Flood (Smurf)", Category: "DoS/DDoS", MitreIDs: []string{"T1499"}, Description: "ICMP echo request flood.", Parameters: []AttackParam{}},
		{ID: "dos-http-flood", Name: "HTTP/S Flood (Layer 7)", Category: "DoS/DDoS", MitreIDs: []string{"T1499.001"}, Description: "High-volume HTTP GET/POST flood against web server.", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "80"}, {Name: "rps", Type: "int", Default: "5000"}}},
		{ID: "dos-slowloris", Name: "Slowloris (Slow HTTP)", Category: "DoS/DDoS", MitreIDs: []string{"T1499.001"}, Description: "Keep HTTP connections open with partial headers.", Parameters: []AttackParam{{Name: "connections", Type: "int", Default: "200"}}},
		{ID: "dos-amplification", Name: "DNS/NTP Amplification", Category: "DoS/DDoS", MitreIDs: []string{"T1498.002"}, Description: "Reflection amplification attack via open DNS/NTP resolvers.", Parameters: []AttackParam{{Name: "proto", Type: "string", Default: "dns"}}},
		{ID: "dos-http2-reset", Name: "HTTP/2 Rapid Reset (CVE-2023-44487)", Category: "DoS/DDoS", MitreIDs: []string{"T1499.001"}, Description: "Open then immediately RST_STREAM thousands of HTTP/2 streams to exhaust server workers.", Parameters: []AttackParam{{Name: "streams", Type: "int", Default: "10000", Description: "RST streams per second"}}},
		{ID: "dos-ssl-exhaust", Name: "TLS/SSL Renegotiation Exhaustion", Category: "DoS/DDoS", MitreIDs: []string{"T1499.001"}, Description: "Repeated TLS handshake initiation to exhaust server CPU with asymmetric cryptography.", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "443"}}},
		{ID: "dos-memcached-amp", Name: "Memcached Amplification", Category: "DoS/DDoS", MitreIDs: []string{"T1498.002"}, Description: "Exploit open Memcached UDP/11211 reflectors (up to 51200x amplification factor).", Parameters: []AttackParam{{Name: "reflector_ip", Type: "ip", Default: "10.0.0.100", Description: "Memcached reflector IP"}}},
		{ID: "dos-rudy", Name: "R.U.D.Y. Slow POST", Category: "DoS/DDoS", MitreIDs: []string{"T1499.001"}, Description: "Send POST body byte-by-byte at very low rate to hold server threads indefinitely.", Parameters: []AttackParam{{Name: "connections", Type: "int", Default: "100"}}},
		{ID: "dos-ack-flood", Name: "TCP ACK Flood", Category: "DoS/DDoS", MitreIDs: []string{"T1499"}, Description: "Flood stateful firewall with TCP ACK packets to exhaust connection tracking table.", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "80"}, {Name: "pps", Type: "int", Default: "20000"}}},
		{ID: "dos-rst-flood", Name: "TCP RST Injection", Category: "DoS/DDoS", MitreIDs: []string{"T1499"}, Description: "Inject forged TCP RST packets to terminate legitimate established sessions.", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "443"}}},
		// ── Spoofing (8) ──
		{ID: "spoof-arp", Name: "ARP Cache Poisoning", Category: "Spoofing", MitreIDs: []string{"T1557.002"}, Description: "Unsolicited ARP replies to poison the gateway and victims.", Parameters: []AttackParam{{Name: "victim_ip", Type: "ip", Default: "", Required: true}}},
		{ID: "spoof-ipsrc", Name: "IP Source Spoofing", Category: "Spoofing", MitreIDs: []string{"T1036"}, Description: "Forged source IP packets to impersonate trusted hosts.", Parameters: []AttackParam{{Name: "spoof_ip", Type: "ip", Default: "10.0.1.10"}}},
		{ID: "spoof-dns", Name: "DNS Cache Poisoning", Category: "Spoofing", MitreIDs: []string{"T1557.003"}, Description: "Inject forged DNS responses to redirect traffic.", Parameters: []AttackParam{{Name: "target_domain", Type: "string", Default: "corp.local"}}},
		{ID: "spoof-mac", Name: "MAC Spoofing", Category: "Spoofing", MitreIDs: []string{"T1036"}, Description: "Clone a trusted device MAC address to bypass MAC filtering.", Parameters: []AttackParam{{Name: "target_mac", Type: "string", Default: "00:11:22:33:44:05"}}},
		{ID: "spoof-dhcp-starve", Name: "DHCP Starvation", Category: "Spoofing", MitreIDs: []string{"T1557"}, Description: "Exhaust DHCP pool with DISCOVER requests using random MAC addresses.", Parameters: []AttackParam{}},
		{ID: "spoof-dhcp-rogue", Name: "Rogue DHCP Server", Category: "Spoofing", MitreIDs: []string{"T1557"}, Description: "Broadcast forged DHCP OFFER to redirect default gateway and DNS server.", Parameters: []AttackParam{{Name: "gateway_spoof", Type: "ip", Default: "10.0.1.99", Description: "Fake gateway IP"}}},
		{ID: "spoof-vlan-hop", Name: "VLAN Hopping (Double Tagging)", Category: "Spoofing", MitreIDs: []string{"T1599"}, Description: "Double 802.1Q tagged frames to reach traffic on a different VLAN.", Parameters: []AttackParam{{Name: "target_vlan", Type: "int", Default: "200", Description: "Target VLAN ID"}}},
		{ID: "spoof-bgp-hijack", Name: "BGP Route Hijack Simulation", Category: "Spoofing", MitreIDs: []string{"T1557"}, Description: "Announce more-specific BGP prefixes to divert traffic through attacker autonomous system.", Parameters: []AttackParam{{Name: "prefix", Type: "string", Default: "10.0.0.0/24", Description: "Hijacked prefix"}}},
		// ── Injection (10) ──
		{ID: "inject-sql", Name: "SQL Injection", Category: "Injection", MitreIDs: []string{"T1190"}, Description: "Classic and blind SQL injection against the web application.", Parameters: []AttackParam{{Name: "endpoint", Type: "string", Default: "/login"}}},
		{ID: "inject-cmd", Name: "OS Command Injection", Category: "Injection", MitreIDs: []string{"T1059"}, Description: "Shell metacharacter injection via vulnerable web parameter.", Parameters: []AttackParam{}},
		{ID: "inject-xss", Name: "Cross-Site Scripting (XSS)", Category: "Injection", MitreIDs: []string{"T1059.007"}, Description: "Reflected XSS payload injection.", Parameters: []AttackParam{}},
		{ID: "inject-ldap", Name: "LDAP Injection", Category: "Injection", MitreIDs: []string{"T1078"}, Description: "LDAP filter injection to bypass authentication.", Parameters: []AttackParam{}},
		{ID: "inject-xxe", Name: "XML External Entity (XXE)", Category: "Injection", MitreIDs: []string{"T1190"}, Description: "XXE payload to read server files or trigger SSRF via vulnerable XML parser.", Parameters: []AttackParam{{Name: "endpoint", Type: "string", Default: "/api/upload", Description: "Target endpoint"}}},
		{ID: "inject-ssti", Name: "Server-Side Template Injection", Category: "Injection", MitreIDs: []string{"T1190"}, Description: "Template expression injection ({{7*7}}) into Jinja2/Twig/Freemarker engines.", Parameters: []AttackParam{{Name: "endpoint", Type: "string", Default: "/search", Description: "Vulnerable endpoint"}}},
		{ID: "inject-lfi", Name: "Local File Inclusion / Path Traversal", Category: "Injection", MitreIDs: []string{"T1190"}, Description: "Directory traversal (../etc/passwd) and PHP LFI to read sensitive files.", Parameters: []AttackParam{{Name: "endpoint", Type: "string", Default: "/view?file=", Description: "Vulnerable parameter"}}},
		{ID: "inject-ssrf", Name: "Server-Side Request Forgery (SSRF)", Category: "Injection", MitreIDs: []string{"T1190"}, Description: "Force the server to make internal requests to metadata endpoints or internal services.", Parameters: []AttackParam{{Name: "target_url", Type: "string", Default: "http://169.254.169.254/latest/meta-data/", Description: "SSRF target URL"}}},
		{ID: "inject-nosql", Name: "NoSQL Injection", Category: "Injection", MitreIDs: []string{"T1190"}, Description: "MongoDB/Redis operator injection ($ne, $gt) to bypass auth or dump collections.", Parameters: []AttackParam{{Name: "endpoint", Type: "string", Default: "/api/users", Description: "Target endpoint"}}},
		{ID: "inject-header", Name: "HTTP Response Header Injection", Category: "Injection", MitreIDs: []string{"T1190"}, Description: "Inject CRLF sequences or Host header values for cache poisoning/redirect.", Parameters: []AttackParam{{Name: "endpoint", Type: "string", Default: "/", Description: "Target endpoint"}}},
		// ── Authentication Attacks (14) ──
		{ID: "auth-bruteforce-ssh", Name: "SSH Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.001"}, Description: "Password brute-force against SSH (port 22).", Parameters: []AttackParam{{Name: "wordlist", Type: "string", Default: "common"}, {Name: "rate", Type: "int", Default: "10"}}},
		{ID: "auth-bruteforce-rdp", Name: "RDP Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.001"}, Description: "Password brute-force against RDP (port 3389).", Parameters: []AttackParam{}},
		{ID: "auth-bruteforce-smb", Name: "SMB Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.003"}, Description: "Credential spray against Windows SMB shares.", Parameters: []AttackParam{}},
		{ID: "auth-credstuff", Name: "Credential Stuffing", Category: "Authentication", MitreIDs: []string{"T1110.004"}, Description: "Replay previously breached username/password pairs.", Parameters: []AttackParam{{Name: "list_size", Type: "int", Default: "100"}}},
		{ID: "auth-kerberoasting", Name: "Kerberoasting", Category: "Authentication", MitreIDs: []string{"T1558.003"}, Description: "Request Kerberos service tickets for offline cracking.", Parameters: []AttackParam{}},
		{ID: "auth-passthehash", Name: "Pass-the-Hash", Category: "Authentication", MitreIDs: []string{"T1550.002"}, Description: "Reuse captured NTLM hash to authenticate without cracking.", Parameters: []AttackParam{{Name: "hash", Type: "string", Default: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"}}},
		{ID: "auth-bruteforce-ftp", Name: "FTP Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.001"}, Description: "Password brute-force against FTP server (port 21).", Parameters: []AttackParam{{Name: "rate", Type: "int", Default: "5", Description: "Attempts per second"}}},
		{ID: "auth-bruteforce-telnet", Name: "Telnet Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.001"}, Description: "Password brute-force against Telnet (port 23).", Parameters: []AttackParam{}},
		{ID: "auth-bruteforce-smtp", Name: "SMTP AUTH Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.001"}, Description: "AUTH LOGIN/PLAIN brute-force against SMTP submission (port 587).", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "587", Description: "SMTP port"}}},
		{ID: "auth-bruteforce-snmp", Name: "SNMP Community String Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.001"}, Description: "Brute-force common SNMP community strings for read/write access.", Parameters: []AttackParam{}},
		{ID: "auth-bruteforce-winrm", Name: "WinRM Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.001"}, Description: "Password brute-force against Windows Remote Management (port 5985/5986).", Parameters: []AttackParam{{Name: "target_port", Type: "int", Default: "5985", Description: "WinRM port"}}},
		{ID: "auth-bruteforce-vnc", Name: "VNC Brute Force", Category: "Authentication", MitreIDs: []string{"T1110.001"}, Description: "Password brute-force against VNC remote desktop (port 5900).", Parameters: []AttackParam{}},
		{ID: "auth-passtheticket", Name: "Pass-the-Ticket", Category: "Authentication", MitreIDs: []string{"T1550.003"}, Description: "Inject a stolen Kerberos TGT or service ticket to impersonate a user.", Parameters: []AttackParam{{Name: "user", Type: "string", Default: "admin@corp.local", Description: "Impersonated user"}}},
		{ID: "auth-asreproast", Name: "AS-REP Roasting", Category: "Authentication", MitreIDs: []string{"T1558.004"}, Description: "Request TGTs for accounts without pre-auth enabled for offline cracking.", Parameters: []AttackParam{}},
		// ── C2 / Malware (12) ──
		{ID: "c2-beaconing", Name: "C2 Beaconing", Category: "C2", MitreIDs: []string{"T1071.001", "T1571"}, Description: "Periodic HTTPS/HTTP beacon to a command-and-control server.", Parameters: []AttackParam{{Name: "interval_secs", Type: "int", Default: "60"}, {Name: "jitter_pct", Type: "int", Default: "20"}, {Name: "count", Type: "int", Default: "10"}}},
		{ID: "c2-dga", Name: "DGA (Domain Generation)", Category: "C2", MitreIDs: []string{"T1568.002"}, Description: "Algorithmically generated domain lookups to locate C2.", Parameters: []AttackParam{{Name: "seed", Type: "string", Default: "xorshift42"}, {Name: "count", Type: "int", Default: "50"}}},
		{ID: "c2-dns-tunnel", Name: "DNS Tunneling", Category: "C2", MitreIDs: []string{"T1071.004"}, Description: "Covert data channel via DNS TXT/CNAME queries.", Parameters: []AttackParam{{Name: "domain", Type: "string", Default: "tunnel.evil.example"}, {Name: "count", Type: "int", Default: "30"}}},
		{ID: "c2-http-covert", Name: "HTTP Covert Channel", Category: "C2", MitreIDs: []string{"T1001.003"}, Description: "Data hidden in HTTP headers or chunked encoding.", Parameters: []AttackParam{{Name: "count", Type: "int", Default: "20"}}},
		{ID: "c2-icmp-tunnel", Name: "ICMP Tunneling", Category: "C2", MitreIDs: []string{"T1095"}, Description: "Covert C2 channel encoded inside ICMP echo request/reply payloads.", Parameters: []AttackParam{{Name: "count", Type: "int", Default: "30", Description: "Number of ICMP tunneled packets"}}},
		{ID: "c2-smb-channel", Name: "SMB Named Pipe C2", Category: "C2", MitreIDs: []string{"T1071"}, Description: "Command-and-control traffic hidden in SMB named pipe read/write operations.", Parameters: []AttackParam{{Name: "pipe_name", Type: "string", Default: "\\PIPE\\srvsvc", Description: "Named pipe path"}}},
		{ID: "c2-websocket", Name: "WebSocket C2 Channel", Category: "C2", MitreIDs: []string{"T1071.001"}, Description: "Persistent bidirectional C2 channel over WebSocket (ws:// or wss://).", Parameters: []AttackParam{{Name: "count", Type: "int", Default: "20", Description: "Beacon messages"}}},
		{ID: "c2-domain-front", Name: "Domain Fronting", Category: "C2", MitreIDs: []string{"T1090.004"}, Description: "Route C2 traffic through CDN (Cloudflare/Akamai) to disguise true destination.", Parameters: []AttackParam{{Name: "front_domain", Type: "string", Default: "cdn.example.com"}, {Name: "count", Type: "int", Default: "10"}}},
		{ID: "c2-reverse-shell", Name: "Reverse Shell Beacon", Category: "C2", MitreIDs: []string{"T1059", "T1571"}, Description: "Simulate reverse shell callback over TCP to attacker listener.", Parameters: []AttackParam{{Name: "port", Type: "int", Default: "4444", Description: "Listener port"}, {Name: "count", Type: "int", Default: "5"}}},
		{ID: "c2-powershell", Name: "PowerShell Encoded C2", Category: "C2", MitreIDs: []string{"T1059.001", "T1132.001"}, Description: "Base64-encoded PowerShell commands delivered over HTTPS to C2 server.", Parameters: []AttackParam{{Name: "count", Type: "int", Default: "15", Description: "Beacon count"}}},
		{ID: "c2-exfil-dns", Name: "DNS Data Exfiltration", Category: "C2", MitreIDs: []string{"T1048.003"}, Description: "Encode and exfiltrate data in DNS query subdomains (base32 chunks).", Parameters: []AttackParam{{Name: "domain", Type: "string", Default: "exfil.evil.example"}, {Name: "data_kb", Type: "int", Default: "50", Description: "KB to exfiltrate"}}},
		{ID: "c2-exfil-icmp", Name: "ICMP Data Exfiltration", Category: "C2", MitreIDs: []string{"T1048.003"}, Description: "Encode stolen data in ICMP echo request payload fields.", Parameters: []AttackParam{{Name: "data_kb", Type: "int", Default: "20", Description: "KB to exfiltrate"}}},
		// ── Lateral Movement / Exfiltration (12) ──
		{ID: "lateral-smb", Name: "SMB Lateral Movement", Category: "Lateral Movement", MitreIDs: []string{"T1021.002"}, Description: "Copy and execute payload via SMB share (PsExec-style).", Parameters: []AttackParam{{Name: "share", Type: "string", Default: "C$"}}},
		{ID: "lateral-psexec", Name: "Remote Service Execution", Category: "Lateral Movement", MitreIDs: []string{"T1021.002", "T1569.002"}, Description: "Start a remote service on target using admin credentials.", Parameters: []AttackParam{}},
		{ID: "exfil-http", Name: "Data Exfiltration (HTTP/S)", Category: "Lateral Movement", MitreIDs: []string{"T1041"}, Description: "Upload sensitive data to external server via HTTPS POST.", Parameters: []AttackParam{{Name: "data_mb", Type: "int", Default: "100"}}},
		{ID: "lateral-wmi", Name: "WMI Remote Execution", Category: "Lateral Movement", MitreIDs: []string{"T1047"}, Description: "Use WMI (DCOM port 135/49152+) to spawn processes on remote hosts.", Parameters: []AttackParam{}},
		{ID: "lateral-dcom", Name: "DCOM Lateral Movement", Category: "Lateral Movement", MitreIDs: []string{"T1021.003"}, Description: "Instantiate remote DCOM objects (MMC20.Application) to execute commands.", Parameters: []AttackParam{}},
		{ID: "lateral-rdp-hijack", Name: "RDP Session Hijacking", Category: "Lateral Movement", MitreIDs: []string{"T1563.002"}, Description: "Hijack disconnected RDP sessions using tscon.exe without knowing credentials.", Parameters: []AttackParam{}},

		{ID: "exfil-ftp", Name: "FTP Data Exfiltration", Category: "Lateral Movement", MitreIDs: []string{"T1048.003"}, Description: "Upload sensitive files to external FTP server over port 21.", Parameters: []AttackParam{{Name: "data_mb", Type: "int", Default: "50", Description: "MB to exfiltrate"}}},
		{ID: "exfil-smtp", Name: "Email Exfiltration (SMTP)", Category: "Lateral Movement", MitreIDs: []string{"T1048.003"}, Description: "Send sensitive data as email attachments via SMTP.", Parameters: []AttackParam{{Name: "data_mb", Type: "int", Default: "10", Description: "MB to exfiltrate"}}},
		{ID: "lateral-golden-ticket", Name: "Golden Ticket Attack", Category: "Lateral Movement", MitreIDs: []string{"T1558.001"}, Description: "Forge Kerberos TGT using krbtgt NTLM hash for unrestricted domain access.", Parameters: []AttackParam{{Name: "user", Type: "string", Default: "administrator@corp.local", Description: "Impersonated user"}}},
		{ID: "lateral-ssh-tunnel", Name: "SSH Tunneling / Port Forward", Category: "Lateral Movement", MitreIDs: []string{"T1572"}, Description: "Establish SSH local/remote port forwarding to pivot through network segments.", Parameters: []AttackParam{{Name: "local_port", Type: "int", Default: "8080"}, {Name: "remote_port", Type: "int", Default: "3306"}}},
		// ── Wireless (4) ──
		{ID: "wireless-rogue-ap", Name: "Rogue Access Point", Category: "Wireless", MitreIDs: []string{"T1557.003"}, Description: "Broadcast evil-twin SSID to lure clients.", Parameters: []AttackParam{{Name: "ssid", Type: "string", Default: "Corp-WiFi"}}},
		{ID: "wireless-deauth", Name: "Wi-Fi Deauthentication Flood", Category: "Wireless", MitreIDs: []string{"T1498"}, Description: "Send 802.11 deauth frames to disconnect clients.", Parameters: []AttackParam{{Name: "ap_name", Type: "string", Default: "ap-floor1"}}},
		{ID: "wireless-pmkid", Name: "PMKID Attack (WPA2)", Category: "Wireless", MitreIDs: []string{"T1110"}, Description: "Capture WPA2 PMKID from EAPOL frame for offline cracking without requiring a client.", Parameters: []AttackParam{{Name: "ap_name", Type: "string", Default: "ap-floor1"}}},
		{ID: "wireless-evil-twin", Name: "Evil Twin with Captive Portal", Category: "Wireless", MitreIDs: []string{"T1557.003"}, Description: "Broadcast identical SSID with stronger signal and serve fake credential-harvesting portal.", Parameters: []AttackParam{{Name: "ssid", Type: "string", Default: "Corp-WiFi"}}},
		// ── Evasion (4) ──
		{ID: "evade-fragmentation", Name: "IP Fragmentation Evasion", Category: "Evasion", MitreIDs: []string{"T1036"}, Description: "Fragment TCP payloads at IP layer to evade signature-based IDS reassembly rules.", Parameters: []AttackParam{{Name: "frag_size", Type: "int", Default: "8", Description: "Fragment size (bytes)"}}},
		{ID: "evade-protocol-tunnel", Name: "Protocol Tunneling (IPv6-in-IPv4)", Category: "Evasion", MitreIDs: []string{"T1572"}, Description: "Encapsulate attacker traffic inside IPv6-in-IPv4 tunnel (protocol 41) to bypass IPv4 filters.", Parameters: []AttackParam{}},
		{ID: "evade-low-slow", Name: "Low-and-Slow Scan", Category: "Evasion", MitreIDs: []string{"T1046"}, Description: "Port scan at very low rate (1 probe/sec) to stay below rate-based IDS detection thresholds.", Parameters: []AttackParam{{Name: "delay_ms", Type: "int", Default: "1000", Description: "Delay between probes (ms)"}, {Name: "ports", Type: "int", Default: "100", Description: "Ports to scan"}}},
		{ID: "evade-decoy", Name: "Decoy Scan", Category: "Evasion", MitreIDs: []string{"T1046"}, Description: "Intermix real scan with packets from random decoy source IPs (nmap -D RND:10 style).", Parameters: []AttackParam{{Name: "decoy_count", Type: "int", Default: "10", Description: "Number of decoy IPs"}}},
	}
}

// lookupAttack finds an attack definition by ID.
func lookupAttack(attackID string) *AttackDefinition {
	for _, atk := range GlobalAttackRegistry {
		if atk.ID == attackID {
			return atk
		}
	}
	return nil
}

// getAttackParam reads a parameter from the request map with a fallback default.
func getAttackParam(params map[string]string, key, defaultVal string) string {
	if val, ok := params[key]; ok && val != "" {
		return val
	}
	return defaultVal
}

// getAttackParamInt reads an integer attack parameter.
func getAttackParamInt(params map[string]string, key string, defaultVal int) int {
	val := getAttackParam(params, key, fmt.Sprintf("%d", defaultVal))
	result := defaultVal
	fmt.Sscanf(val, "%d", &result)
	return result
}
