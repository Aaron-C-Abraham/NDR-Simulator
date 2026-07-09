// packet_listener.go
// Standalone UDP listener for NDR-Simulator packet stream.
// Run: go run packet_listener.go --port 9999
// Start ndr_sim with: ./ndr_sim --stream-host 127.0.0.1 --stream-port 9999
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	port := flag.Int("port", 9999, "UDP port to listen on")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve error: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("=== NDR-Sim Packet Listener ===\n")
	fmt.Printf("Listening on UDP port %d...\n\n", *port)
	fmt.Printf("%-26s %-10s %-21s %-21s %-6s %s\n",
		"TIMESTAMP", "PROTO", "SRC", "DST", "LEN", "INFO")
	fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────")

	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			continue
		}
		parseAndPrint(buf[:n])
	}
}

func parseAndPrint(pkt []byte) {
	ts := time.Now().Format("15:04:05.000000")

	// Must be at least Ethernet header (14 bytes)
	if len(pkt) < 14 {
		fmt.Printf("%-26s %-10s [too short: %d bytes]\n", ts, "RAW", len(pkt))
		return
	}

	etherType := binary.BigEndian.Uint16(pkt[12:14])

	// Handle 802.1Q VLAN tag
	payload := pkt[14:]
	if etherType == 0x8100 && len(pkt) >= 18 {
		etherType = binary.BigEndian.Uint16(pkt[16:18])
		payload = pkt[18:]
	}
	switch etherType {
	case 0x0800: // IPv4
		parseIPv4(ts, payload)
	case 0x0806: // ARP
		parseARP(ts, payload)
	case 0x86DD: // IPv6
		fmt.Printf("%-26s %-10s %-21s %-21s\n", ts, "IPv6", "-", "-")
	case 0xBBCC, 0x2B3C, 0x2233: // 802.11 wireless frames (link type 105)
		parse80211(ts, pkt)
	default:
		fmt.Printf("%-26s %-10s EtherType=0x%04X len=%d\n", ts, "UNKNOWN", etherType, len(pkt))
	}
}

func parse80211(ts string, frame []byte) {
	if len(frame) < 4 {
		fmt.Printf("%-26s %-10s [truncated 802.11]\n", ts, "802.11")
		return
	}
	frameCtrl := binary.BigEndian.Uint16(frame[0:2])
	frameType := (frameCtrl >> 2) & 0x03
	frameSubtype := (frameCtrl >> 4) & 0x0F

	var info string
	switch frameType {
	case 0: // Management
		switch frameSubtype {
		case 8:
			info = "Beacon"
		case 12:
			info = "Deauth"
		case 11:
			info = "Auth"
		case 0:
			info = "Assoc Request"
		case 1:
			info = "Assoc Response"
		default:
			info = fmt.Sprintf("Mgmt subtype=%d", frameSubtype)
		}
	case 1: // Control
		info = fmt.Sprintf("Control subtype=%d", frameSubtype)
	case 2: // Data
		info = fmt.Sprintf("Data subtype=%d", frameSubtype)
	default:
		info = fmt.Sprintf("type=%d subtype=%d", frameType, frameSubtype)
	}

	src, dst := "-", "-"
	if len(frame) >= 16 {
		dst = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			frame[4], frame[5], frame[6], frame[7], frame[8], frame[9])
		src = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			frame[10], frame[11], frame[12], frame[13], frame[14], frame[15])
	}

	fmt.Printf("%-26s %-10s %-21s %-21s %-6d %s\n",
		ts, "802.11", src, dst, len(frame), info)
}

func parseIPv4(ts string, ip []byte) {
	if len(ip) < 20 {
		fmt.Printf("%-26s %-10s [truncated IPv4]\n", ts, "IPv4")
		return
	}

	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || ihl > len(ip) {
		fmt.Printf("%-26s %-10s [bad IHL]\n", ts, "IPv4")
		return
	}

	proto := ip[9]
	totalLen := binary.BigEndian.Uint16(ip[2:4])
	srcIP := net.IP(ip[12:16]).String()
	dstIP := net.IP(ip[16:20]).String()
	transport := ip[ihl:]

	switch proto {
	case 1: // ICMP
		icmpType := ""
		if len(transport) >= 1 {
			switch transport[0] {
			case 0:
				icmpType = "Echo Reply"
			case 8:
				icmpType = "Echo Request"
			case 3:
				icmpType = "Dest Unreachable"
			default:
				icmpType = fmt.Sprintf("Type=%d", transport[0])
			}
		}
		fmt.Printf("%-26s %-10s %-21s %-21s %-6d %s\n",
			ts, "ICMP", srcIP, dstIP, totalLen, icmpType)

	case 6: // TCP
		if len(transport) < 20 {
			fmt.Printf("%-26s %-10s %-21s %-21s %-6d [truncated TCP]\n", ts, "TCP", srcIP, dstIP, totalLen)
			return
		}
		srcPort := binary.BigEndian.Uint16(transport[0:2])
		dstPort := binary.BigEndian.Uint16(transport[2:4])
		flags := transport[13]
		flagStr := tcpFlags(flags)
		info := fmt.Sprintf("[%s] %s", flagStr, tcpServiceHint(dstPort))
		fmt.Printf("%-26s %-10s %-21s %-21s %-6d %s\n",
			ts, "TCP",
			fmt.Sprintf("%s:%d", srcIP, srcPort),
			fmt.Sprintf("%s:%d", dstIP, dstPort),
			totalLen, info)

	case 17: // UDP
		if len(transport) < 8 {
			fmt.Printf("%-26s %-10s %-21s %-21s %-6d [truncated UDP]\n", ts, "UDP", srcIP, dstIP, totalLen)
			return
		}
		srcPort := binary.BigEndian.Uint16(transport[0:2])
		dstPort := binary.BigEndian.Uint16(transport[2:4])
		info := udpServiceHint(dstPort)
		fmt.Printf("%-26s %-10s %-21s %-21s %-6d %s\n",
			ts, "UDP",
			fmt.Sprintf("%s:%d", srcIP, srcPort),
			fmt.Sprintf("%s:%d", dstIP, dstPort),
			totalLen, info)

	case 41: // IPv6-in-IPv4
		fmt.Printf("%-26s %-10s %-21s %-21s %-6d IPv6-in-IPv4 tunnel\n",
			ts, "IPv6/IP", srcIP, dstIP, totalLen)

	default:
		fmt.Printf("%-26s %-10s %-21s %-21s %-6d proto=%d\n",
			ts, "IPv4", srcIP, dstIP, totalLen, proto)
	}
}

func parseARP(ts string, arp []byte) {
	if len(arp) < 28 {
		fmt.Printf("%-26s %-10s [truncated ARP]\n", ts, "ARP")
		return
	}
	op := binary.BigEndian.Uint16(arp[6:8])
	srcIP := net.IP(arp[14:18]).String()
	dstIP := net.IP(arp[24:28]).String()
	opStr := "Request"
	if op == 2 {
		opStr = "Reply"
	}
	fmt.Printf("%-26s %-10s %-21s %-21s %-6s %s\n",
		ts, "ARP", srcIP, dstIP, "-", opStr)
}

func tcpFlags(f byte) string {
	flags := ""
	if f&0x02 != 0 {
		flags += "SYN "
	}
	if f&0x10 != 0 {
		flags += "ACK "
	}
	if f&0x08 != 0 {
		flags += "PSH "
	}
	if f&0x01 != 0 {
		flags += "FIN "
	}
	if f&0x04 != 0 {
		flags += "RST "
	}
	if flags == "" {
		flags = "NONE"
	}
	return flags
}

func tcpServiceHint(port uint16) string {
	switch port {
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 88:
		return "Kerberos"
	case 135:
		return "DCOM/RPC"
	case 139:
		return "NetBIOS"
	case 143:
		return "IMAP"
	case 179:
		return "BGP"
	case 389:
		return "LDAP"
	case 443:
		return "HTTPS/TLS"
	case 445:
		return "SMB"
	case 587:
		return "SMTP-Submission"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 4444:
		return "Reverse-Shell"
	case 5985:
		return "WinRM"
	case 5900:
		return "VNC"
	case 8080:
		return "HTTP-Alt"
	case 8443:
		return "HTTPS-Alt"
	default:
		return ""
	}
}

func udpServiceHint(port uint16) string {
	switch port {
	case 53:
		return "DNS"
	case 67:
		return "DHCP-Server"
	case 68:
		return "DHCP-Client"
	case 88:
		return "Kerberos"
	case 123:
		return "NTP"
	case 137:
		return "NetBIOS-NS"
	case 138:
		return "NetBIOS-DGM"
	case 161:
		return "SNMP"
	case 162:
		return "SNMP-Trap"
	case 11211:
		return "Memcached"
	default:
		return ""
	}
}
