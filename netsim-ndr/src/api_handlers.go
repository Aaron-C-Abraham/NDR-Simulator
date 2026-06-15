// Package main — api_handlers.go
// All Gin HTTP handler functions for topology, attacks, scenarios, runs, and NDR alert ingestion.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ─── Topology Handlers ────────────────────────────────────────────────────────

func handleListDevices(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleListDevices")
	devices := getAllDevices()
	ginCtx.JSON(http.StatusOK, gin.H{"devices": devices, "total": len(devices)})
	logInfo("Return from handleListDevices count=%d", len(devices))
}

func handleGetDevice(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	deviceID := ginCtx.Param("id")
	logInfo("Entering handleGetDevice id=%s", deviceID)
	dev, ok := getDevice(deviceID)
	if !ok {
		ginCtx.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	ginCtx.JSON(http.StatusOK, dev)
	logInfo("Return from handleGetDevice id=%s", deviceID)
}

func handleCreateDevice(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleCreateDevice")
	var dev Device
	if err := ginCtx.ShouldBindJSON(&dev); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := saveDevice(&dev); err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeAuditLog("api", "device_created", dev.Name, dev)
	broadcastEvent("device_added", dev)
	go GlobalSNMPAgent.rebuildOIDTree()
	ginCtx.JSON(http.StatusCreated, dev)
	logInfo("Return from handleCreateDevice id=%s name=%s", dev.ID, dev.Name)
}

func handleUpdateDevice(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	deviceID := ginCtx.Param("id")
	logInfo("Entering handleUpdateDevice id=%s", deviceID)
	var dev Device
	if err := ginCtx.ShouldBindJSON(&dev); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	dev.ID = deviceID
	if err := saveDevice(&dev); err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeAuditLog("api", "device_updated", dev.Name, dev)
	broadcastEvent("device_updated", dev)
	go GlobalSNMPAgent.rebuildOIDTree()
	ginCtx.JSON(http.StatusOK, dev)
	logInfo("Return from handleUpdateDevice id=%s", deviceID)
}

func handleDeleteDevice(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	deviceID := ginCtx.Param("id")
	logInfo("Entering handleDeleteDevice id=%s", deviceID)
	if err := deleteDevice(deviceID); err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeAuditLog("api", "device_deleted", deviceID, nil)
	broadcastEvent("device_deleted", gin.H{"id": deviceID})
	go GlobalSNMPAgent.rebuildOIDTree()
	ginCtx.JSON(http.StatusOK, gin.H{"deleted": deviceID})
	logInfo("Return from handleDeleteDevice id=%s", deviceID)
}

func handleTopologyGraph(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleTopologyGraph")
	graph := buildTopologyGraph()
	ginCtx.JSON(http.StatusOK, graph)
	logInfo("Return from handleTopologyGraph nodes=%d edges=%d", len(graph.Nodes), len(graph.Edges))
}

func handleTopologySummary(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleTopologySummary")
	summary := buildTopologySummary()
	ginCtx.JSON(http.StatusOK, summary)
	logInfo("Return from handleTopologySummary")
}

// ─── Attack Handlers ─────────────────────────────────────────────────────────

func handleListAttacks(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleListAttacks")
	category := ginCtx.Query("category")
	var attacks []*AttackDefinition
	for _, atk := range GlobalAttackRegistry {
		if category == "" || atk.Category == category {
			attacks = append(attacks, atk)
		}
	}
	ginCtx.JSON(http.StatusOK, gin.H{"attacks": attacks, "total": len(attacks)})
	logInfo("Return from handleListAttacks count=%d", len(attacks))
}

func handleGetAttack(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	attackID := ginCtx.Param("id")
	logInfo("Entering handleGetAttack id=%s", attackID)
	atk := lookupAttack(attackID)
	if atk == nil {
		ginCtx.JSON(http.StatusNotFound, gin.H{"error": "attack not found"})
		return
	}
	ginCtx.JSON(http.StatusOK, atk)
	logInfo("Return from handleGetAttack id=%s", attackID)
}

func handleExecuteAttack(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleExecuteAttack")
	var req AttackRequest
	if err := ginCtx.ShouldBindJSON(&req); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, ok := req.Params["port_range"]
	if ok {
		portRange, _ := req.Params["port_range"]
		low_up := strings.Split(portRange, "-")
		if len(low_up) != 2 {
			ginCtx.JSON(http.StatusBadRequest, gin.H{"error": "invalid port_range_value format, expected 'low-high'"})
			return
		}
		lower_range, err := strconv.Atoi(low_up[0])
		upper_range, err2 := strconv.Atoi(low_up[1])
		if err != nil || err2 != nil || lower_range < 1 || upper_range > 65535 || lower_range >= upper_range {
			ginCtx.JSON(http.StatusBadRequest, gin.H{"error": "invalid port_range_value, ports must be between 1 and 65535 and low must be less than high"})
			return
		}
		logInfo("Port range attack requested,Lower=%d Upper=%d", lower_range, upper_range)
	}

	def := lookupAttack(req.AttackID)
	if def == nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": "unknown attack_id: " + req.AttackID})
		return
	}
	if len(req.TargetIPs) == 0 {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": "target_ips required"})
		return
	}

	result, err := executeAttack(req)
	saveAttackExecution(result, def.Name, def.Category)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "result": result})
		return
	}
	broadcastEvent("attack_completed", result)
	ginCtx.JSON(http.StatusOK, result)
	logInfo("Return from handleExecuteAttack attackID=%s", req.AttackID)
}

// AttackExecution is a persisted record of a single attack execution.
type AttackExecution struct {
	ID          int64    `json:"id"`
	AttackID    string   `json:"attack_id"`
	AttackName  string   `json:"attack_name"`
	Category    string   `json:"category"`
	AttackerIP  string   `json:"attacker_ip"`
	TargetIPs   []string `json:"target_ips"`
	Status      string   `json:"status"`
	SyslogCount int      `json:"syslog_count"`
	FlowCount   int      `json:"flow_count"`
	PCAPFiles   []string `json:"pcap_files"`
	ErrorMsg    string   `json:"error_msg,omitempty"`
	StartedAt   string   `json:"started_at"`
	CompletedAt string   `json:"completed_at"`
	DurationMS  int64    `json:"duration_ms"`
	CreatedAt   string   `json:"created_at"`
}

// saveAttackExecution persists an AttackResult to the attack_executions table.
func saveAttackExecution(result *AttackResult, attackName, category string) {
	defer panicHandler(traceFunc(), nil)
	if result == nil {
		return
	}
	logInfo("Entering saveAttackExecution attackID=%s", result.AttackID)

	targetJSON, _ := json.Marshal(result.TargetIPs)
	pcapJSON, _ := json.Marshal(result.PCAPFiles)
	status := "success"
	if result.Error != "" {
		status = "error"
	}
	durationMS := result.CompletedAt.Sub(result.StartedAt).Milliseconds()

	_, err := GlobalDB.Exec(`
		INSERT INTO attack_executions
			(attack_id, attack_name, category, attacker_ip, target_ips, status,
			 syslog_count, flow_count, pcap_files, error_msg, started_at, completed_at, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		result.AttackID, attackName, category, result.AttackerIP,
		string(targetJSON), status,
		result.SyslogCount, result.FlowCount, string(pcapJSON),
		result.Error,
		result.StartedAt.UTC().Format(time.RFC3339),
		result.CompletedAt.UTC().Format(time.RFC3339),
		durationMS,
	)
	if err != nil {
		logError("saveAttackExecution exec: %v", err)
	}
	logInfo("Return from saveAttackExecution attackID=%s status=%s", result.AttackID, status)
}

// getAttackHistoryDB returns the most recent attack executions.
func getAttackHistoryDB(limit int) ([]AttackExecution, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getAttackHistoryDB limit=%d", limit)

	if limit <= 0 {
		limit = 100
	}
	rows, err := GlobalDB.Query(`
		SELECT id, attack_id, attack_name, category, attacker_ip, target_ips,
		       status, syslog_count, flow_count, pcap_files, error_msg,
		       started_at, completed_at, duration_ms, created_at
		FROM attack_executions
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		logError("getAttackHistoryDB query: %v", err)
		return nil, err
	}
	defer rows.Close()

	var list []AttackExecution
	for rows.Next() {
		var ex AttackExecution
		var targetJSON, pcapJSON string
		if err := rows.Scan(
			&ex.ID, &ex.AttackID, &ex.AttackName, &ex.Category, &ex.AttackerIP, &targetJSON,
			&ex.Status, &ex.SyslogCount, &ex.FlowCount, &pcapJSON, &ex.ErrorMsg,
			&ex.StartedAt, &ex.CompletedAt, &ex.DurationMS, &ex.CreatedAt,
		); err != nil {
			logError("getAttackHistoryDB scan: %v", err)
			continue
		}
		json.Unmarshal([]byte(targetJSON), &ex.TargetIPs)
		json.Unmarshal([]byte(pcapJSON), &ex.PCAPFiles)
		list = append(list, ex)
	}
	logInfo("Return from getAttackHistoryDB count=%d", len(list))
	return list, nil
}

// handleGetAttackHistory returns a paginated list of past attack executions.
func handleGetAttackHistory(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetAttackHistory")

	limitStr := ginCtx.DefaultQuery("limit", "100")
	var limit int
	fmt.Sscan(limitStr, &limit)

	history, err := getAttackHistoryDB(limit)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if history == nil {
		history = []AttackExecution{}
	}
	ginCtx.JSON(http.StatusOK, gin.H{"history": history, "total": len(history)})
	logInfo("Return from handleGetAttackHistory count=%d", len(history))
}

// ─── Scenario Handlers ────────────────────────────────────────────────────────

func handleListScenarios(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleListScenarios")
	scenarios, err := loadAllScenariosDB()
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.JSON(http.StatusOK, gin.H{"scenarios": scenarios, "total": len(scenarios)})
	logInfo("Return from handleListScenarios count=%d", len(scenarios))
}

func handleGetScenario(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	scenarioID := ginCtx.Param("id")
	logInfo("Entering handleGetScenario id=%s", scenarioID)
	def, err := getScenarioDB(scenarioID)
	if err != nil {
		ginCtx.JSON(http.StatusNotFound, gin.H{"error": "scenario not found"})
		return
	}
	ginCtx.JSON(http.StatusOK, def)
	logInfo("Return from handleGetScenario id=%s", scenarioID)
}

func handleCreateScenario(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleCreateScenario")
	var def ScenarioDefinition
	if err := ginCtx.ShouldBindJSON(&def); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateScenario(&def); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := saveScenarioDB(&def); err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeAuditLog("api", "scenario_created", def.Name, def)
	ginCtx.JSON(http.StatusCreated, def)
	logInfo("Return from handleCreateScenario id=%s", def.ID)
}

func handleUpdateScenario(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	scenarioID := ginCtx.Param("id")
	logInfo("Entering handleUpdateScenario id=%s", scenarioID)
	var def ScenarioDefinition
	if err := ginCtx.ShouldBindJSON(&def); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	def.ID = scenarioID
	if err := saveScenarioDB(&def); err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.JSON(http.StatusOK, def)
	logInfo("Return from handleUpdateScenario id=%s", scenarioID)
}

func handleDeleteScenario(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	scenarioID := ginCtx.Param("id")
	logInfo("Entering handleDeleteScenario id=%s", scenarioID)
	_, err := GlobalDB.Exec(`DELETE FROM scenarios WHERE id=?`, scenarioID)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	writeAuditLog("api", "scenario_deleted", scenarioID, nil)
	ginCtx.JSON(http.StatusOK, gin.H{"deleted": scenarioID})
	logInfo("Return from handleDeleteScenario id=%s", scenarioID)
}

// ─── Run Handlers ─────────────────────────────────────────────────────────────

func handleListRuns(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleListRuns")
	statusFilter := ginCtx.Query("status")
	runs, err := getTestRunsDB(statusFilter)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.JSON(http.StatusOK, gin.H{"runs": runs, "total": len(runs)})
	logInfo("Return from handleListRuns count=%d", len(runs))
}

func handleGetRun(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	runID := ginCtx.Param("id")
	logInfo("Entering handleGetRun id=%s", runID)
	run, err := getTestRunDB(runID)
	if err != nil {
		ginCtx.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	ginCtx.JSON(http.StatusOK, run)
	logInfo("Return from handleGetRun id=%s", runID)
}

// StartRunRequest is the API request body for starting a test run.
type StartRunRequest struct {
	ScenarioID string   `json:"scenario_id" binding:"required"`
	AttackerIP string   `json:"attacker_ip"`
	TargetIPs  []string `json:"target_ips"`
}

func handleStartRun(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleStartRun")
	var req StartRunRequest
	if err := ginCtx.ShouldBindJSON(&req); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	def, err := getScenarioDB(req.ScenarioID)
	if err != nil {
		ginCtx.JSON(http.StatusNotFound, gin.H{"error": "scenario not found: " + req.ScenarioID})
		return
	}

	attackerIP := req.AttackerIP
	if attackerIP == "" {
		attackerIP = getAttackerDevice().IPAddress
	}
	targetIPs := req.TargetIPs
	if len(targetIPs) == 0 {
		targetIPs = getWorkstationIPs()
	}

	run, err := createTestRun(def, attackerIP, targetIPs)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	go executeScenario(run)
	writeAuditLog("api", "run_started", run.ID, run)
	broadcastEvent("run_started", run)
	ginCtx.JSON(http.StatusCreated, run)
	logInfo("Return from handleStartRun runID=%s", run.ID)
}

func handleAbortRun(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	runID := ginCtx.Param("id")
	logInfo("Entering handleAbortRun id=%s", runID)
	abortRun(runID)
	broadcastEvent("run_aborted", gin.H{"run_id": runID})
	ginCtx.JSON(http.StatusOK, gin.H{"aborted": runID})
	logInfo("Return from handleAbortRun id=%s", runID)
}

func handleGetRunEvents(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	runID := ginCtx.Param("id")
	logInfo("Entering handleGetRunEvents id=%s", runID)
	events, err := getRunEventsDB(runID)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.JSON(http.StatusOK, gin.H{"events": events, "total": len(events)})
	logInfo("Return from handleGetRunEvents count=%d", len(events))
}

// ─── NDR Alert Ingestion ──────────────────────────────────────────────────────

// ingestNDRAlert stores an alert received from the NDR sensor in the ndr_alerts table.
func ingestNDRAlert(runID, alertType, severity, sourceIP, destIP, mitreID, description string, payload map[string]interface{}) error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering ingestNDRAlert type=%s run=%s src=%s", alertType, runID, sourceIP)

	rawJSON, _ := json.Marshal(payload)
	_, err := GlobalDB.Exec(`
		INSERT INTO ndr_alerts (run_id, alert_time, alert_type, severity, source_ip, dest_ip, mitre_id, description, raw_payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		runID, time.Now().UTC().Format(time.RFC3339), alertType, severity, sourceIP, destIP, mitreID, description, string(rawJSON))
	if err != nil {
		logError("ingestNDRAlert exec: %v", err)
		return err
	}
	writeAuditLog("ndr", "alert_ingested", alertType, map[string]string{"run_id": runID, "src": sourceIP})
	logInfo("Return from ingestNDRAlert type=%s run=%s", alertType, runID)
	return nil
}

// AlertIngestRequest is the payload posted by the NDR agent when it fires an alert.
type AlertIngestRequest struct {
	RunID       string                 `json:"run_id"`
	AlertType   string                 `json:"alert_type"`
	Severity    string                 `json:"severity"`
	SourceIP    string                 `json:"source_ip"`
	DestIP      string                 `json:"dest_ip"`
	MitreID     string                 `json:"mitre_id"`
	Description string                 `json:"description"`
	Payload     map[string]interface{} `json:"payload"`
}

func handleIngestAlert(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleIngestAlert")
	var req AlertIngestRequest
	if err := ginCtx.ShouldBindJSON(&req); err != nil {
		// Also try reading raw JSON body
		var rawPayload map[string]interface{}
		if bodyErr := ginCtx.ShouldBindJSON(&rawPayload); bodyErr != nil {
			ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		req = mapToAlertRequest(rawPayload)
	}

	if err := ingestNDRAlert(req.RunID, req.AlertType, req.Severity, req.SourceIP, req.DestIP, req.MitreID, req.Description, req.Payload); err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	broadcastEvent("ndr_alert", req)
	ginCtx.JSON(http.StatusCreated, gin.H{"ingested": true})
	logInfo("Return from handleIngestAlert type=%s run=%s", req.AlertType, req.RunID)
}

// ─── SNMP Agent Handlers ──────────────────────────────────────────────────────

func handleGetSNMPStatus(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetSNMPStatus")
	status := getSNMPAgentStatus()
	ginCtx.JSON(http.StatusOK, status)
	logInfo("Return from handleGetSNMPStatus running=%v oids=%d", status.Running, status.OIDCount)
}

func handleRebuildSNMPTree(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleRebuildSNMPTree")
	GlobalSNMPAgent.rebuildOIDTree()
	status := getSNMPAgentStatus()
	ginCtx.JSON(http.StatusOK, status)
	logInfo("Return from handleRebuildSNMPTree oids=%d", status.OIDCount)
}

// mapToAlertRequest attempts to coerce a generic map to an AlertIngestRequest.
func mapToAlertRequest(raw map[string]interface{}) AlertIngestRequest {
	getString := func(key string) string {
		if val, ok := raw[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
		return ""
	}
	payloadJSON, _ := json.Marshal(raw)
	var payload map[string]interface{}
	json.Unmarshal(payloadJSON, &payload)
	return AlertIngestRequest{
		RunID:       getString("run_id"),
		AlertType:   getString("alert_type"),
		Severity:    getString("severity"),
		SourceIP:    getString("source_ip"),
		DestIP:      getString("dest_ip"),
		MitreID:     getString("mitre_id"),
		Description: getString("description"),
		Payload:     payload,
	}
}
