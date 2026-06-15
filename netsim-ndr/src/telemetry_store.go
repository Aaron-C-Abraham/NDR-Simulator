// Package main — telemetry_store.go
// Persists syslog messages and flow records to SQLite; provides retrieve and PCAP listing.
package main

import (
	"os"
	"strings"
	"time"
)

// StoredSyslogMessage is a syslog event persisted in the database.
type StoredSyslogMessage struct {
	ID         int64     `json:"id"`
	DeviceIP   string    `json:"device_ip"`
	DeviceName string    `json:"device_name"`
	Format     string    `json:"format"`
	Severity   int       `json:"severity"`
	Message    string    `json:"message"`
	Raw        string    `json:"raw"`
	CreatedAt  time.Time `json:"created_at"`
}

// StoredFlowRecord is a flow record persisted in the database.
type StoredFlowRecord struct {
	ID         int64     `json:"id"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Protocol   uint8     `json:"protocol"`
	Bytes      uint32    `json:"bytes"`
	Packets    uint32    `json:"packets"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	ExporterIP string    `json:"exporter_ip"`
	FlowType   string    `json:"flow_type"`
	CreatedAt  time.Time `json:"created_at"`
}

// PCAPFileInfo holds metadata about a PCAP output file.
type PCAPFileInfo struct {
	Filename  string    `json:"filename"`
	Size      int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	URL       string    `json:"url"`
}

// TelemetryStats holds aggregate telemetry counters.
type TelemetryStats struct {
	TotalSyslog   int64 `json:"total_syslog"`
	TotalFlows    int64 `json:"total_flows"`
	TotalPCAP     int   `json:"total_pcap"`
	PCAPSizeBytes int64 `json:"pcap_size_bytes"`
}

// storeSyslogMessage persists a SyslogEvent to the database.
func storeSyslogMessage(event *SyslogEvent) {
	defer panicHandler(traceFunc(), nil)
	if GlobalDB == nil {
		return
	}
	rawMsg := event.Raw
	if len(rawMsg) > 4096 {
		rawMsg = rawMsg[:4096]
	}
	_, err := GlobalDB.Exec(
		`INSERT INTO syslog_messages (device_ip, device_name, format, severity, message, raw) VALUES (?,?,?,?,?,?)`,
		event.DeviceIP, event.DeviceName, event.Format, event.Severity, event.Message, rawMsg,
	)
	if err != nil {
		logError("storeSyslogMessage: %v", err)
	}
}

// storeFlowRecord persists a FlowRecord to the database.
func storeFlowRecord(flow FlowRecord, exporterIP, flowType string) {
	defer panicHandler(traceFunc(), nil)
	if GlobalDB == nil {
		return
	}
	_, err := GlobalDB.Exec(
		`INSERT INTO flow_records (src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, start_time, end_time, exporter_ip, flow_type) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		flow.SrcIP, flow.DstIP, flow.SrcPort, flow.DstPort, flow.Protocol,
		flow.Bytes, flow.Packets,
		flow.StartTime.UTC().Format(time.RFC3339),
		flow.EndTime.UTC().Format(time.RFC3339),
		exporterIP, flowType,
	)
	if err != nil {
		logError("storeFlowRecord: %v", err)
		return
	}
	broadcastEvent("flow_received", map[string]interface{}{
		"src_ip":      flow.SrcIP,
		"dst_ip":      flow.DstIP,
		"src_port":    flow.SrcPort,
		"dst_port":    flow.DstPort,
		"protocol":    flow.Protocol,
		"bytes":       flow.Bytes,
		"packets":     flow.Packets,
		"flow_type":   flowType,
		"exporter_ip": exporterIP,
		"created_at":  time.Now(),
	})
}

// getRecentSyslogMessages retrieves the most recent syslog messages.
func getRecentSyslogMessages(limit int, deviceFilter, formatFilter string) ([]StoredSyslogMessage, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getRecentSyslogMessages limit=%d device=%s format=%s", limit, deviceFilter, formatFilter)

	query := `SELECT id, device_ip, device_name, format, severity, message, raw, created_at FROM syslog_messages`
	var args []interface{}
	var conditions []string
	if deviceFilter != "" {
		conditions = append(conditions, "device_ip=?")
		args = append(args, deviceFilter)
	}
	if formatFilter != "" {
		conditions = append(conditions, "format=?")
		args = append(args, formatFilter)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := GlobalDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []StoredSyslogMessage
	for rows.Next() {
		var msg StoredSyslogMessage
		var createdAtStr string
		if err := rows.Scan(&msg.ID, &msg.DeviceIP, &msg.DeviceName, &msg.Format,
			&msg.Severity, &msg.Message, &msg.Raw, &createdAtStr); err != nil {
			continue
		}
		msg.CreatedAt, _ = parseTimeStr(createdAtStr)
		messages = append(messages, msg)
	}
	logInfo("Return from getRecentSyslogMessages count=%d", len(messages))
	return messages, nil
}

// getRecentFlowRecords retrieves the most recent flow records.
func getRecentFlowRecords(limit int, srcFilter, dstFilter, flowTypeFilter string) ([]StoredFlowRecord, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getRecentFlowRecords limit=%d", limit)

	query := `SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, start_time, end_time, exporter_ip, flow_type, created_at FROM flow_records`
	var args []interface{}
	var conditions []string
	if srcFilter != "" {
		conditions = append(conditions, "src_ip=?")
		args = append(args, srcFilter)
	}
	if dstFilter != "" {
		conditions = append(conditions, "dst_ip=?")
		args = append(args, dstFilter)
	}
	if flowTypeFilter != "" {
		conditions = append(conditions, "flow_type=?")
		args = append(args, flowTypeFilter)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := GlobalDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var flows []StoredFlowRecord
	for rows.Next() {
		var flow StoredFlowRecord
		var startStr, endStr, createdAtStr string
		if err := rows.Scan(&flow.ID, &flow.SrcIP, &flow.DstIP, &flow.SrcPort, &flow.DstPort,
			&flow.Protocol, &flow.Bytes, &flow.Packets,
			&startStr, &endStr, &flow.ExporterIP, &flow.FlowType, &createdAtStr); err != nil {
			continue
		}
		flow.StartTime, _ = parseTimeStr(startStr)
		flow.EndTime, _ = parseTimeStr(endStr)
		flow.CreatedAt, _ = parseTimeStr(createdAtStr)
		flows = append(flows, flow)
	}
	logInfo("Return from getRecentFlowRecords count=%d", len(flows))
	return flows, nil
}

// getPCAPFiles lists PCAP files in the output directory.
func getPCAPFiles() ([]PCAPFileInfo, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getPCAPFiles")

	pcapDir := configString("output.pcap.dir", "output/pcap")
	entries, err := os.ReadDir(pcapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []PCAPFileInfo{}, nil
		}
		return nil, err
	}

	var files []PCAPFileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".pcap") && !strings.HasSuffix(name, ".pcapng") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, PCAPFileInfo{
			Filename:  name,
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
			URL:       "/api/v1/telemetry/pcap/" + name,
		})
	}
	logInfo("Return from getPCAPFiles count=%d", len(files))
	return files, nil
}

// getTelemetryStats returns aggregate telemetry counters.
func getTelemetryStats() TelemetryStats {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getTelemetryStats")

	var stats TelemetryStats
	GlobalDB.QueryRow(`SELECT COUNT(*) FROM syslog_messages`).Scan(&stats.TotalSyslog)
	GlobalDB.QueryRow(`SELECT COUNT(*) FROM flow_records`).Scan(&stats.TotalFlows)

	pcapFiles, _ := getPCAPFiles()
	stats.TotalPCAP = len(pcapFiles)
	for _, f := range pcapFiles {
		stats.PCAPSizeBytes += f.Size
	}

	logInfo("Return from getTelemetryStats syslog=%d flows=%d pcap=%d", stats.TotalSyslog, stats.TotalFlows, stats.TotalPCAP)
	return stats
}

// getAuditLogEntries retrieves recent audit log entries.
func getAuditLogEntries(limit int) ([]map[string]interface{}, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getAuditLogEntries limit=%d", limit)

	rows, err := GlobalDB.Query(
		`SELECT id, actor, action, resource, detail, created_at FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []map[string]interface{}
	for rows.Next() {
		var id int64
		var actor, action, resource, detail, createdAt string
		if err := rows.Scan(&id, &actor, &action, &resource, &detail, &createdAt); err != nil {
			continue
		}
		entries = append(entries, map[string]interface{}{
			"id":         id,
			"actor":      actor,
			"action":     action,
			"resource":   resource,
			"detail":     detail,
			"created_at": createdAt,
		})
	}
	logInfo("Return from getAuditLogEntries count=%d", len(entries))
	return entries, nil
}

