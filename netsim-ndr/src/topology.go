// Package main — topology.go
// Device topology management: in-memory model + SQLite persistence.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Device represents a simulated network node.
type Device struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	DeviceType  string          `json:"device_type"`
	IPAddress   string          `json:"ip_address"`
	MACAddress  string          `json:"mac_address"`
	OSType      string          `json:"os_type"`
	Vendor      string          `json:"vendor"`
	NetworkZone string          `json:"network_zone"`
	Telemetry   DeviceTelemetry `json:"telemetry"`
	Status      string          `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// DeviceTelemetry describes which telemetry formats the device emits.
type DeviceTelemetry struct {
	Syslog  bool `json:"syslog"`
	Netflow bool `json:"netflow"`
	Sflow   bool `json:"sflow"`
	Pcap    bool `json:"pcap"`
}

// GlobalTopologyMap is the in-memory device map indexed by device ID.
var GlobalTopologyMap = map[string]*Device{}

// GlobalTopologyMapLock protects GlobalTopologyMap.
var GlobalTopologyMapLock sync.RWMutex

// loadTopology populates the in-memory map from SQLite.
func loadTopology() error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering loadTopology")

	rows, err := GlobalDB.Query(
		`SELECT id, name, device_type, ip_address, mac_address, os_type, vendor, network_zone, telemetry, status, created_at, updated_at FROM devices WHERE status != 'deleted'`)
	if err != nil {
		logError("loadTopology query: %v", err)
		return err
	}
	defer rows.Close()

	GlobalTopologyMapLock.Lock()
	defer GlobalTopologyMapLock.Unlock()

	count := 0
	for rows.Next() {
		var dev Device
		var telemetryJSON, createdAtStr, updatedAtStr string
		if err = rows.Scan(&dev.ID, &dev.Name, &dev.DeviceType, &dev.IPAddress, &dev.MACAddress,
			&dev.OSType, &dev.Vendor, &dev.NetworkZone, &telemetryJSON,
			&dev.Status, &createdAtStr, &updatedAtStr); err != nil {
			logError("loadTopology scan: %v", err)
			continue
		}
		dev.CreatedAt, _ = parseTimeStr(createdAtStr)
		dev.UpdatedAt, _ = parseTimeStr(updatedAtStr)
		if err = json.Unmarshal([]byte(telemetryJSON), &dev.Telemetry); err != nil {
			logWarn("loadTopology telemetry unmarshal: %v", err)
		}
		GlobalTopologyMap[dev.ID] = &dev
		count++
	}
	logInfo("Return from loadTopology devices=%d", count)
	return nil
}

// getDevice returns a device by ID from the in-memory map.
func getDevice(deviceID string) (*Device, bool) {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	dev, ok := GlobalTopologyMap[deviceID]
	return dev, ok
}

// getAllDevices returns a copy of all devices.
func getAllDevices() []*Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	result := make([]*Device, 0, len(GlobalTopologyMap))
	for _, dev := range GlobalTopologyMap {
		result = append(result, dev)
	}
	return result
}

// getDevicesByZone returns all devices in a given network zone.
func getDevicesByZone(zone string) []*Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var result []*Device
	for _, dev := range GlobalTopologyMap {
		if dev.NetworkZone == zone {
			result = append(result, dev)
		}
	}
	return result
}

// getDeviceByIP returns a device matching the given IP.
func getDeviceByIP(ip string) (*Device, bool) {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	for _, dev := range GlobalTopologyMap {
		if dev.IPAddress == ip {
			return dev, true
		}
	}
	return nil, false
}

// saveDevice persists a new or updated device to SQLite and updates the in-memory map.
func saveDevice(dev *Device) error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering saveDevice name=%s", dev.Name)

	if dev.ID == "" {
		dev.ID = uuid.New().String()
	}
	dev.UpdatedAt = time.Now()

	telemetryJSON, err := marshalJSON(dev.Telemetry)
	if err != nil {
		logError("saveDevice marshal telemetry: %v", err)
		return err
	}

	_, err = GlobalDB.Exec(`
		INSERT OR REPLACE INTO devices (id, name, device_type, ip_address, mac_address, os_type, vendor, network_zone, telemetry, status)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		dev.ID, dev.Name, dev.DeviceType, dev.IPAddress, dev.MACAddress,
		dev.OSType, dev.Vendor, dev.NetworkZone, string(telemetryJSON), dev.Status)
	if err != nil {
		logError("saveDevice exec: %v", err)
		return err
	}

	GlobalTopologyMapLock.Lock()
	GlobalTopologyMap[dev.ID] = dev
	GlobalTopologyMapLock.Unlock()

	logInfo("Return from saveDevice id=%s", dev.ID)
	return nil
}

// deleteDevice marks a device as deleted in SQLite and removes it from memory.
func deleteDevice(deviceID string) error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering deleteDevice id=%s", deviceID)

	_, err := GlobalDB.Exec(`UPDATE devices SET status='deleted' WHERE id=?`, deviceID)
	if err != nil {
		logError("deleteDevice exec: %v", err)
		return err
	}

	GlobalTopologyMapLock.Lock()
	delete(GlobalTopologyMap, deviceID)
	GlobalTopologyMapLock.Unlock()

	logInfo("Return from deleteDevice id=%s", deviceID)
	return nil
}

// seedDefaultTopology inserts the 24-device reference topology if the devices table is empty.
func seedDefaultTopology() error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering seedDefaultTopology")

	var count int
	err := GlobalDB.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		logInfo("Return from seedDefaultTopology already seeded count=%d", count)
		return nil
	}

	defaultDevices := buildDefaultDevices()
	for _, dev := range defaultDevices {
		if err := saveDevice(dev); err != nil {
			logError("seedDefaultTopology saveDevice %s: %v", dev.Name, err)
		}
	}
	logInfo("Return from seedDefaultTopology seeded=%d", len(defaultDevices))
	return nil
}

// buildDefaultDevices returns the 24-node reference topology.
func buildDefaultDevices() []*Device {
	return []*Device{
		{Name: "gw-internet", DeviceType: "router", IPAddress: "203.0.113.1", MACAddress: "00:11:22:33:44:01", OSType: "IOS 16.9", Vendor: "Cisco", NetworkZone: "external", Status: "active", Telemetry: DeviceTelemetry{Syslog: true, Netflow: true}},
		{Name: "fw-perimeter", DeviceType: "firewall", IPAddress: "10.0.0.1", MACAddress: "00:11:22:33:44:02", OSType: "FortiOS 7.4", Vendor: "Fortinet", NetworkZone: "dmz", Status: "active", Telemetry: DeviceTelemetry{Syslog: true, Netflow: true, Pcap: true}},
		{Name: "sw-core", DeviceType: "switch", IPAddress: "10.0.1.1", MACAddress: "00:11:22:33:44:03", OSType: "EOS 4.27", Vendor: "Arista", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true, Sflow: true}},
		{Name: "sw-dmz", DeviceType: "switch", IPAddress: "10.0.2.1", MACAddress: "00:11:22:33:44:04", OSType: "EOS 4.27", Vendor: "Arista", NetworkZone: "dmz", Status: "active", Telemetry: DeviceTelemetry{Syslog: true, Sflow: true}},
		{Name: "dc-primary", DeviceType: "server", IPAddress: "10.0.1.10", MACAddress: "00:11:22:33:44:05", OSType: "Windows Server 2022", Vendor: "Microsoft", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "dc-secondary", DeviceType: "server", IPAddress: "10.0.1.11", MACAddress: "00:11:22:33:44:06", OSType: "Windows Server 2022", Vendor: "Microsoft", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "web-server", DeviceType: "server", IPAddress: "10.0.2.10", MACAddress: "00:11:22:33:44:07", OSType: "Ubuntu 22.04", Vendor: "Canonical", NetworkZone: "dmz", Status: "active", Telemetry: DeviceTelemetry{Syslog: true, Pcap: true}},
		{Name: "db-server", DeviceType: "server", IPAddress: "10.0.1.20", MACAddress: "00:11:22:33:44:08", OSType: "RHEL 9", Vendor: "Red Hat", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "file-server", DeviceType: "server", IPAddress: "10.0.1.21", MACAddress: "00:11:22:33:44:09", OSType: "Windows Server 2019", Vendor: "Microsoft", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "mail-server", DeviceType: "server", IPAddress: "10.0.2.11", MACAddress: "00:11:22:33:44:0a", OSType: "Ubuntu 22.04", Vendor: "Canonical", NetworkZone: "dmz", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "ws-finance-01", DeviceType: "workstation", IPAddress: "10.0.3.101", MACAddress: "00:11:22:33:44:11", OSType: "Windows 11", Vendor: "Microsoft", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "ws-finance-02", DeviceType: "workstation", IPAddress: "10.0.3.102", MACAddress: "00:11:22:33:44:12", OSType: "Windows 11", Vendor: "Microsoft", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "ws-hr-01", DeviceType: "workstation", IPAddress: "10.0.3.103", MACAddress: "00:11:22:33:44:13", OSType: "Windows 10", Vendor: "Microsoft", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "ws-dev-01", DeviceType: "workstation", IPAddress: "10.0.3.104", MACAddress: "00:11:22:33:44:14", OSType: "Ubuntu 22.04", Vendor: "Canonical", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "laptop-mgr-01", DeviceType: "workstation", IPAddress: "10.0.3.105", MACAddress: "00:11:22:33:44:15", OSType: "macOS 14", Vendor: "Apple", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "ap-floor1", DeviceType: "wireless_ap", IPAddress: "10.0.4.1", MACAddress: "00:11:22:33:44:16", OSType: "AireOS 8.10", Vendor: "Cisco", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "ap-floor2", DeviceType: "wireless_ap", IPAddress: "10.0.4.2", MACAddress: "00:11:22:33:44:17", OSType: "AireOS 8.10", Vendor: "Cisco", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "dns-server", DeviceType: "server", IPAddress: "10.0.1.53", MACAddress: "00:11:22:33:44:18", OSType: "Ubuntu 22.04", Vendor: "Canonical", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true, Pcap: true}},
		{Name: "ntp-server", DeviceType: "server", IPAddress: "10.0.1.123", MACAddress: "00:11:22:33:44:19", OSType: "Ubuntu 22.04", Vendor: "Canonical", NetworkZone: "internal", Status: "active", Telemetry: DeviceTelemetry{Syslog: true}},
		{Name: "iot-camera-01", DeviceType: "iot", IPAddress: "10.0.5.1", MACAddress: "00:11:22:33:44:20", OSType: "Embedded Linux", Vendor: "Hikvision", NetworkZone: "internal", Status: "active"},
		{Name: "iot-hvac", DeviceType: "iot", IPAddress: "10.0.5.2", MACAddress: "00:11:22:33:44:21", OSType: "Embedded RTOS", Vendor: "Honeywell", NetworkZone: "internal", Status: "active"},
		{Name: "attacker-ext", DeviceType: "workstation", IPAddress: "198.51.100.100", MACAddress: "00:aa:bb:cc:dd:01", OSType: "Kali Linux 2024", Vendor: "Offensive Security", NetworkZone: "external", Status: "active"},
		{Name: "c2-server", DeviceType: "server", IPAddress: "198.51.100.200", MACAddress: "00:aa:bb:cc:dd:02", OSType: "Ubuntu 22.04", Vendor: "Unknown", NetworkZone: "external", Status: "active"},
		{Name: "vpn-gateway", DeviceType: "router", IPAddress: "10.0.0.2", MACAddress: "00:11:22:33:44:24", OSType: "FortiOS 7.4", Vendor: "Fortinet", NetworkZone: "dmz", Status: "active", Telemetry: DeviceTelemetry{Syslog: true, Netflow: true}},
	}
}

// marshalJSON is a helper that serializes a value to JSON bytes.
func marshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// TopologySummary describes aggregate stats for the dashboard.
type TopologySummary struct {
	TotalDevices   int            `json:"total_devices"`
	ByZone         map[string]int `json:"by_zone"`
	ByType         map[string]int `json:"by_type"`
	SyslogEnabled  int            `json:"syslog_enabled"`
	NetflowEnabled int            `json:"netflow_enabled"`
	SflowEnabled   int            `json:"sflow_enabled"`
	PcapEnabled    int            `json:"pcap_enabled"`
}

// buildTopologySummary aggregates device stats from the in-memory map.
func buildTopologySummary() TopologySummary {
	defer panicHandler(traceFunc(), nil)
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()

	summary := TopologySummary{
		ByZone: map[string]int{},
		ByType: map[string]int{},
	}
	for _, dev := range GlobalTopologyMap {
		summary.TotalDevices++
		summary.ByZone[dev.NetworkZone]++
		summary.ByType[dev.DeviceType]++
		if dev.Telemetry.Syslog {
			summary.SyslogEnabled++
		}
		if dev.Telemetry.Netflow {
			summary.NetflowEnabled++
		}
		if dev.Telemetry.Sflow {
			summary.SflowEnabled++
		}
		if dev.Telemetry.Pcap {
			summary.PcapEnabled++
		}
	}
	return summary
}

// getAttackerDevice returns the canonical external attacker device.
func getAttackerDevice() *Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	for _, dev := range GlobalTopologyMap {
		if dev.NetworkZone == "external" && dev.DeviceType == "workstation" {
			return dev
		}
	}
	return &Device{Name: "attacker-ext", IPAddress: "198.51.100.100", MACAddress: "00:aa:bb:cc:dd:01", NetworkZone: "external"}
}

// validateIPInTopology checks if an IP address exists in the topology.
func validateIPInTopology(ip string) bool {
	_, found := getDeviceByIP(ip)
	return found
}

// describeTopologyEdges returns the logical connections between devices.
func describeTopologyEdges() []map[string]string {
	edges := []map[string]string{
		{"source": "gw-internet", "target": "fw-perimeter", "link": "WAN"},
		{"source": "fw-perimeter", "target": "sw-dmz", "link": "DMZ trunk"},
		{"source": "fw-perimeter", "target": "sw-core", "link": "Internal trunk"},
		{"source": "fw-perimeter", "target": "vpn-gateway", "link": "VPN"},
		{"source": "sw-dmz", "target": "web-server", "link": "eth"},
		{"source": "sw-dmz", "target": "mail-server", "link": "eth"},
		{"source": "sw-core", "target": "dc-primary", "link": "eth"},
		{"source": "sw-core", "target": "dc-secondary", "link": "eth"},
		{"source": "sw-core", "target": "db-server", "link": "eth"},
		{"source": "sw-core", "target": "file-server", "link": "eth"},
		{"source": "sw-core", "target": "dns-server", "link": "eth"},
		{"source": "sw-core", "target": "ntp-server", "link": "eth"},
		{"source": "sw-core", "target": "ws-finance-01", "link": "eth"},
		{"source": "sw-core", "target": "ws-finance-02", "link": "eth"},
		{"source": "sw-core", "target": "ws-hr-01", "link": "eth"},
		{"source": "sw-core", "target": "ws-dev-01", "link": "eth"},
		{"source": "sw-core", "target": "laptop-mgr-01", "link": "eth"},
		{"source": "sw-core", "target": "ap-floor1", "link": "eth"},
		{"source": "sw-core", "target": "ap-floor2", "link": "eth"},
		{"source": "sw-core", "target": "iot-camera-01", "link": "eth"},
		{"source": "sw-core", "target": "iot-hvac", "link": "eth"},
	}
	return edges
}

// TopologyGraph is the full topology for the frontend vis.
type TopologyGraph struct {
	Nodes []map[string]interface{} `json:"nodes"`
	Edges []map[string]string      `json:"edges"`
}

// buildTopologyGraph returns nodes + edges for visualization.
func buildTopologyGraph() TopologyGraph {
	defer panicHandler(traceFunc(), nil)
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()

	graph := TopologyGraph{
		Edges: describeTopologyEdges(),
	}
	for _, dev := range GlobalTopologyMap {
		node := map[string]interface{}{
			"id":           dev.ID,
			"name":         dev.Name,
			"device_type":  dev.DeviceType,
			"ip_address":   dev.IPAddress,
			"network_zone": dev.NetworkZone,
			"vendor":       dev.Vendor,
			"status":       dev.Status,
		}
		graph.Nodes = append(graph.Nodes, node)
	}
	return graph
}

// getInternalServerIPs returns IP addresses of all internal servers.
func getInternalServerIPs() []string {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var ips []string
	for _, dev := range GlobalTopologyMap {
		if dev.NetworkZone == "internal" && dev.DeviceType == "server" {
			ips = append(ips, dev.IPAddress)
		}
	}
	return ips
}

// getWorkstationIPs returns IP addresses of all workstations.
func getWorkstationIPs() []string {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var ips []string
	for _, dev := range GlobalTopologyMap {
		if dev.DeviceType == "workstation" && dev.NetworkZone == "internal" {
			ips = append(ips, dev.IPAddress)
		}
	}
	return ips
}

// pickRandomDevice returns a random active device from the map.
func pickRandomDevice() *Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	devices := make([]*Device, 0, len(GlobalTopologyMap))
	for _, dev := range GlobalTopologyMap {
		if dev.Status == "active" {
			devices = append(devices, dev)
		}
	}
	if len(devices) == 0 {
		return nil
	}
	return devices[randIntn(len(devices))]
}

// deviceIPMap returns a map of device name → IP for quick lookup.
func deviceIPMap() map[string]string {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	result := make(map[string]string, len(GlobalTopologyMap))
	for _, dev := range GlobalTopologyMap {
		result[dev.Name] = dev.IPAddress
	}
	return result
}

// Sentinel to avoid import cycle — actual random call is through randIntn.
var randIntn = func(n int) int {
	return int(time.Now().UnixNano()) % n
}

// topologyDeviceExists returns true if a device ID exists in the topology.
func topologyDeviceExists(id string) bool {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	_, ok := GlobalTopologyMap[id]
	return ok
}

// lookupDeviceName returns the name for a device IP, or the IP itself if not found.
func lookupDeviceName(ip string) string {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	for _, dev := range GlobalTopologyMap {
		if dev.IPAddress == ip {
			return dev.Name
		}
	}
	return ip
}

// syslogDevices returns all devices that have syslog telemetry enabled.
func syslogDevices() []*Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var result []*Device
	for _, dev := range GlobalTopologyMap {
		if dev.Telemetry.Syslog {
			result = append(result, dev)
		}
	}
	return result
}

// netflowDevices returns all devices that export NetFlow.
func netflowDevices() []*Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var result []*Device
	for _, dev := range GlobalTopologyMap {
		if dev.Telemetry.Netflow {
			result = append(result, dev)
		}
	}
	return result
}

// pcapDevices returns all devices that generate PCAP.
func pcapDevices() []*Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var result []*Device
	for _, dev := range GlobalTopologyMap {
		if dev.Telemetry.Pcap {
			result = append(result, dev)
		}
	}
	return result
}

// getFirewall returns the perimeter firewall device.
func getFirewall() *Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	for _, dev := range GlobalTopologyMap {
		if dev.DeviceType == "firewall" {
			return dev
		}
	}
	return nil
}

// getRouters returns all router devices.
func getRouters() []*Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var result []*Device
	for _, dev := range GlobalTopologyMap {
		if dev.DeviceType == "router" {
			result = append(result, dev)
		}
	}
	return result
}

func getSwitches() []*Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var result []*Device
	for _, dev := range GlobalTopologyMap {
		if dev.DeviceType == "switch" {
			result = append(result, dev)
		}
	}
	return result
}

// getDNSServer returns the DNS server device.
func getDNSServer() *Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	for _, dev := range GlobalTopologyMap {
		if dev.Name == "dns-server" {
			return dev
		}
	}
	return nil
}

// getCCServer returns the C2 server device.
func getCCServer() *Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	for _, dev := range GlobalTopologyMap {
		if dev.Name == "c2-server" {
			return dev
		}
	}
	return &Device{Name: "c2-server", IPAddress: "198.51.100.200", NetworkZone: "external"}
}

// getWirelessAPs returns all wireless access points.
func getWirelessAPs() []*Device {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var result []*Device
	for _, dev := range GlobalTopologyMap {
		if dev.DeviceType == "wireless_ap" {
			result = append(result, dev)
		}
	}
	return result
}

// domainControllerIPs returns IPs of domain controller servers.
func domainControllerIPs() []string {
	GlobalTopologyMapLock.RLock()
	defer GlobalTopologyMapLock.RUnlock()
	var ips []string
	for _, dev := range GlobalTopologyMap {
		if strings.Contains(dev.Name, "dc-") {
			ips = append(ips, dev.IPAddress)
		}
	}
	return ips
}

// ensure fmt is used
var _ = fmt.Sprintf
