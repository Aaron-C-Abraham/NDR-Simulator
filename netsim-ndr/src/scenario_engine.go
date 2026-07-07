// Package main — scenario_engine.go
// Scenario loading, validation, and execution orchestration.
// A scenario is an ordered sequence of attack steps that together form
// a complete adversary kill-chain simulation.
package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"os"
	"path/filepath"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// ScenarioStep is one attack step inside a scenario.
type ScenarioStep struct {
	AttackID   string            `yaml:"attack_id" json:"attack_id"`
	Name       string            `yaml:"name" json:"name"`
	Delay      int               `yaml:"delay_secs" json:"delay_secs"` // delay before this step
	AttackerIP string            `yaml:"attacker_ip" json:"attacker_ip"`
	TargetIPs  []string          `yaml:"target_ips" json:"target_ips"`
	Params     map[string]string `yaml:"params" json:"params"`
}

// ScenarioDefinition is the parsed scenario YAML/JSON.
type ScenarioDefinition struct {
	ID              string         `yaml:"id" json:"id"`
	Name            string         `yaml:"name" json:"name"`
	Description     string         `yaml:"description" json:"description"`
	Category        string         `yaml:"category" json:"category"`
	MitreTechniques []string       `yaml:"mitre_techniques" json:"mitre_techniques"`
	Steps           []ScenarioStep `yaml:"steps" json:"steps"`
	ExpectedAlerts  []string       `yaml:"expected_alerts" json:"expected_alerts"`
	DurationSecs    int            `yaml:"duration_secs" json:"duration_secs"`
}

// TestRun is the active record for a running scenario.
type TestRun struct {
	ID             string              `json:"id"`
	ScenarioID     string              `json:"scenario_id"`
	ScenarioName   string              `json:"scenario_name"`
	Status         string              `json:"status"`
	StartedAt      *time.Time          `json:"started_at"`
	CompletedAt    *time.Time          `json:"completed_at"`
	DurationSecs   int                 `json:"duration_secs"`
	AttackerIP     string              `json:"attacker_ip"`
	TargetIPs      []string            `json:"target_ips"`
	ConfigSnapshot *ScenarioDefinition `json:"config_snapshot"`
	CreatedAt      time.Time           `json:"created_at"`
}

// GlobalRunMap tracks in-flight runs.
var GlobalRunMap = map[string]*TestRun{}
var GlobalRunMapLock sync.RWMutex

// loadScenarioFromFile reads a YAML scenario definition from disk.
func loadScenarioFromFile(path string) (*ScenarioDefinition, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering loadScenarioFromFile path=%s", path)

	data, err := os.ReadFile(path)
	if err != nil {
		logError("loadScenarioFromFile read: %v", err)
		return nil, err
	}
	var def ScenarioDefinition
	if err = yaml.Unmarshal(data, &def); err != nil {
		logError("loadScenarioFromFile yaml: %v", err)
		return nil, err
	}
	if def.ID == "" {
		def.ID = uuid.New().String()
	}
	logInfo("Return from loadScenarioFromFile name=%s steps=%d", def.Name, len(def.Steps))
	return &def, nil
}

// saveScenarioDB persists a scenario to SQLite.
func saveScenarioDB(def *ScenarioDefinition) error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering saveScenarioDB id=%s name=%s", def.ID, def.Name)

	if def.ID == "" {
		def.ID = uuid.New().String()
	}

	mitreTechJSON, _ := json.Marshal(def.MitreTechniques)
	stepsJSON, _ := json.Marshal(def.Steps)
	alertsJSON, _ := json.Marshal(def.ExpectedAlerts)

	_, err := GlobalDB.Exec(`
		INSERT OR REPLACE INTO scenarios (id, name, description, category, mitre_techniques, attack_steps, expected_alerts, duration_secs)
		VALUES (?,?,?,?,?,?,?,?)`,
		def.ID, def.Name, def.Description, def.Category,
		string(mitreTechJSON), string(stepsJSON), string(alertsJSON), def.DurationSecs)
	if err != nil {
		logError("saveScenarioDB exec: %v", err)
		return err
	}
	logInfo("Return from saveScenarioDB id=%s", def.ID)
	return nil
}

// loadAllScenariosDB returns all scenarios from SQLite.
func loadAllScenariosDB() ([]*ScenarioDefinition, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering loadAllScenariosDB")

	rows, err := GlobalDB.Query(`SELECT id, name, description, category, mitre_techniques, attack_steps, expected_alerts, duration_secs FROM scenarios`)
	if err != nil {
		logError("loadAllScenariosDB query: %v", err)
		return nil, err
	}
	defer rows.Close()

	var result []*ScenarioDefinition
	for rows.Next() {
		var def ScenarioDefinition
		var mitreTechJSON, stepsJSON, alertsJSON string
		if err = rows.Scan(&def.ID, &def.Name, &def.Description, &def.Category, &mitreTechJSON, &stepsJSON, &alertsJSON, &def.DurationSecs); err != nil {
			logError("loadAllScenariosDB scan: %v", err)
			continue
		}
		json.Unmarshal([]byte(mitreTechJSON), &def.MitreTechniques)
		json.Unmarshal([]byte(stepsJSON), &def.Steps)
		json.Unmarshal([]byte(alertsJSON), &def.ExpectedAlerts)
		result = append(result, &def)
	}
	logInfo("Return from loadAllScenariosDB count=%d", len(result))
	return result, nil
}

// getScenarioDB loads a single scenario by ID from SQLite.
func getScenarioDB(scenarioID string) (*ScenarioDefinition, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getScenarioDB id=%s", scenarioID)

	var def ScenarioDefinition
	var mitreTechJSON, stepsJSON, alertsJSON string
	err := GlobalDB.QueryRow(`SELECT id, name, description, category, mitre_techniques, attack_steps, expected_alerts, duration_secs FROM scenarios WHERE id=?`, scenarioID).
		Scan(&def.ID, &def.Name, &def.Description, &def.Category, &mitreTechJSON, &stepsJSON, &alertsJSON, &def.DurationSecs)
	if err != nil {
		logError("getScenarioDB scan: %v", err)
		return nil, err
	}
	json.Unmarshal([]byte(mitreTechJSON), &def.MitreTechniques)
	json.Unmarshal([]byte(stepsJSON), &def.Steps)
	json.Unmarshal([]byte(alertsJSON), &def.ExpectedAlerts)
	logInfo("Return from getScenarioDB name=%s", def.Name)
	return &def, nil
}

// createTestRun creates a new TestRun record in SQLite and memory.
func createTestRun(def *ScenarioDefinition, attackerIP string, targetIPs []string) (*TestRun, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering createTestRun scenario=%s attacker=%s targets=%v", def.Name, attackerIP, targetIPs)

	run := &TestRun{
		ID:             uuid.New().String(),
		ScenarioID:     def.ID,
		ScenarioName:   def.Name,
		Status:         "pending",
		AttackerIP:     attackerIP,
		TargetIPs:      targetIPs,
		ConfigSnapshot: def,
		CreatedAt:      time.Now(),
	}

	targetIPsJSON, _ := json.Marshal(targetIPs)
	configJSON, _ := json.Marshal(def)

	_, err := GlobalDB.Exec(`
		INSERT INTO test_runs (id, scenario_id, scenario_name, status, attacker_ip, target_ips, config_snapshot)
		VALUES (?,?,?,?,?,?,?)`,
		run.ID, run.ScenarioID, run.ScenarioName, run.Status,
		run.AttackerIP, string(targetIPsJSON), string(configJSON))
	if err != nil {
		logError("createTestRun exec: %v", err)
		return nil, err
	}

	GlobalRunMapLock.Lock()
	GlobalRunMap[run.ID] = run
	GlobalRunMapLock.Unlock()

	logInfo("Return from createTestRun runID=%s", run.ID)
	return run, nil
}

// updateRunStatus updates the status of a test run in SQLite and memory.
func updateRunStatus(runID, status string) error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering updateRunStatus runID=%s status=%s", runID, status)

	var err error
	if status == "running" {
		now := time.Now()
		_, err = GlobalDB.Exec(`UPDATE test_runs SET status=?, started_at=? WHERE id=?`, status, now.UTC().Format(time.RFC3339), runID)
		GlobalRunMapLock.Lock()
		if run, ok := GlobalRunMap[runID]; ok {
			run.Status = status
			run.StartedAt = &now
		}
		GlobalRunMapLock.Unlock()
	} else if status == "completed" || status == "failed" || status == "aborted" {
		now := time.Now()
		GlobalRunMapLock.RLock()
		run := GlobalRunMap[runID]
		GlobalRunMapLock.RUnlock()
		var durationSecs int
		if run != nil && run.StartedAt != nil {
			durationSecs = int(now.Sub(*run.StartedAt).Seconds())
		}
		_, err = GlobalDB.Exec(`UPDATE test_runs SET status=?, completed_at=?, duration_secs=? WHERE id=?`,
			status, now.UTC().Format(time.RFC3339), durationSecs, runID)
		GlobalRunMapLock.Lock()
		if r, ok := GlobalRunMap[runID]; ok {
			r.Status = status
			r.CompletedAt = &now
			r.DurationSecs = durationSecs
		}
		GlobalRunMapLock.Unlock()
	} else {
		_, err = GlobalDB.Exec(`UPDATE test_runs SET status=? WHERE id=?`, status, runID)
		GlobalRunMapLock.Lock()
		if run, ok := GlobalRunMap[runID]; ok {
			run.Status = status
		}
		GlobalRunMapLock.Unlock()
	}

	if err != nil {
		logError("updateRunStatus exec: %v", err)
	}
	logInfo("Return from updateRunStatus runID=%s status=%s", runID, status)
	return err
}

// executeScenario runs all steps of a scenario in sequence in a background goroutine.
func executeScenario(run *TestRun) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering executeScenario runID=%s scenario=%s", run.ID, run.ScenarioName)

	GlobalActiveAttacksLock.Lock()
	GlobalActiveAttacks[run.ID] = true
	GlobalActiveAttacksLock.Unlock()

	updateRunStatus(run.ID, "running")

	def := run.ConfigSnapshot
	for idx, step := range def.Steps {
		logInfo("executeScenario runID=%s step=%d/%d attack=%s", run.ID, idx+1, len(def.Steps), step.AttackID)

		// Check abort
		GlobalActiveAttacksLock.Lock()
		active := GlobalActiveAttacks[run.ID]
		GlobalActiveAttacksLock.Unlock()
		if !active {
			logInfo("executeScenario runID=%s aborted at step %d", run.ID, idx+1)
			updateRunStatus(run.ID, "aborted")
			return
		}

		// Inter-step delay
		if step.Delay > 0 {
			time.Sleep(time.Duration(step.Delay) * time.Second)
		}

		// Resolve attacker IP
		attackerIP := step.AttackerIP
		if attackerIP == "" {
			attackerIP = run.AttackerIP
		}
		// Resolve target IPs
		targetIPs := step.TargetIPs
		if len(targetIPs) == 0 {
			targetIPs = run.TargetIPs
		}

		req := AttackRequest{
			AttackID:   step.AttackID,
			RunID:      run.ID,
			AttackerIP: attackerIP,
			TargetIPs:  targetIPs,
			Params:     step.Params,
		}
		if req.Params == nil {
			req.Params = map[string]string{}
		}
		_, err := executeAttack(req)
		if err != nil {
			logError("executeScenario step %d failed: %v", idx+1, err)
		}
	}

	updateRunStatus(run.ID, "completed")

	GlobalActiveAttacksLock.Lock()
	delete(GlobalActiveAttacks, run.ID)
	GlobalActiveAttacksLock.Unlock()

	logInfo("Return from executeScenario runID=%s", run.ID)
}

// abortRun signals the running scenario to stop after the current step.
func abortRun(runID string) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering abortRun runID=%s", runID)
	GlobalActiveAttacksLock.Lock()
	GlobalActiveAttacks[runID] = false
	GlobalActiveAttacksLock.Unlock()
	logInfo("Return from abortRun runID=%s", runID)
}

// getTestRun returns a run by ID.
func getTestRun(runID string) (*TestRun, bool) {
	GlobalRunMapLock.RLock()
	defer GlobalRunMapLock.RUnlock()
	run, ok := GlobalRunMap[runID]
	return run, ok
}

// loadBuiltInScenarios seeds the pre-built scenarios from the scenarios/ directory.
func loadBuiltInScenarios() {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering loadBuiltInScenarios")

	scenarioDir := configString("sim.topology.file", "scenarios")
	scenarioDir = filepath.Dir(scenarioDir)

	files, err := filepath.Glob(filepath.Join(scenarioDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		logWarn("loadBuiltInScenarios: no YAML files found in %s, seeding defaults", scenarioDir)
		seedBuiltInScenarios()
		return
	}

	for _, file := range files {
		def, err := loadScenarioFromFile(file)
		if err != nil {
			logError("loadBuiltInScenarios load %s: %v", file, err)
			continue
		}
		if err = saveScenarioDB(def); err != nil {
			logError("loadBuiltInScenarios save %s: %v", file, err)
		}
	}
	logInfo("Return from loadBuiltInScenarios files=%d", len(files))
}

// seedBuiltInScenarios inserts the 6 reference TTL scenarios programmatically.
func seedBuiltInScenarios() {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering seedBuiltInScenarios")

	var count int
	GlobalDB.QueryRow(`SELECT COUNT(*) FROM scenarios`).Scan(&count)
	if count > 0 {
		logInfo("Return from seedBuiltInScenarios already seeded count=%d", count)
		return
	}

	scenarios := buildBuiltInScenarios()
	for _, def := range scenarios {
		if err := saveScenarioDB(def); err != nil {
			logError("seedBuiltInScenarios save %s: %v", def.Name, err)
		}
	}
	logInfo("Return from seedBuiltInScenarios seeded=%d", len(scenarios))
}

func buildBuiltInScenarios() []*ScenarioDefinition {
	return []*ScenarioDefinition{
		{
			ID:              uuid.New().String(),
			Name:            "B1 — C2 Beaconing (HTTPS)",
			Description:     "Infected workstation establishes periodic beaconing to external C2 server over HTTPS",
			Category:        "beaconing",
			MitreTechniques: []string{"T1071.001", "T1571"},
			DurationSecs:    300,
			ExpectedAlerts:  []string{"C2 Beaconing Detected", "Periodic Outbound Connection", "Suspicious External Traffic"},
			Steps: []ScenarioStep{
				{AttackID: "recon-portscan", Name: "Initial recon", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.2.10"}, Delay: 0, Params: map[string]string{"port_range": "1-1024"}},
				{AttackID: "c2-beaconing", Name: "C2 Beaconing", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 30, Params: map[string]string{"interval_secs": "60", "count": "5"}},
			},
		},
		{
			ID:              uuid.New().String(),
			Name:            "B2 — DGA-based C2",
			Description:     "Malware uses DGA to generate C2 domains, causing high NXDOMAIN rate",
			Category:        "dga",
			MitreTechniques: []string{"T1568.002", "T1071.004"},
			DurationSecs:    180,
			ExpectedAlerts:  []string{"DGA Detected", "High NXDOMAIN Rate", "Suspicious DNS Activity"},
			Steps: []ScenarioStep{
				{AttackID: "c2-dga", Name: "DGA beacon", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 0, Params: map[string]string{"count": "30"}},
				{AttackID: "c2-dns-tunnel", Name: "DNS tunnel C2", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 30, Params: map[string]string{"domain": "tunnel.evil.example", "count": "20"}},
			},
		},
		{
			ID:              uuid.New().String(),
			Name:            "B3 — Lateral Movement (SMB)",
			Description:     "Attacker moves laterally via SMB pass-the-hash after initial compromise",
			Category:        "lateral_movement",
			MitreTechniques: []string{"T1021.002", "T1550.002", "T1046"},
			DurationSecs:    420,
			ExpectedAlerts:  []string{"Lateral Movement Detected", "Pass-the-Hash", "Anomalous SMB Activity"},
			Steps: []ScenarioStep{
				{AttackID: "recon-portscan", Name: "Internal recon", AttackerIP: "10.0.3.101", TargetIPs: []string{"10.0.1.10", "10.0.1.20"}, Delay: 0, Params: map[string]string{"port_range": "1-1024"}},
				{AttackID: "auth-passthehash", Name: "Pass-the-hash", AttackerIP: "10.0.3.101", TargetIPs: []string{"10.0.1.10"}, Delay: 30},
				{AttackID: "lateral-smb", Name: "SMB lateral to DC", AttackerIP: "10.0.3.101", TargetIPs: []string{"10.0.1.10", "10.0.1.11"}, Delay: 30},
				{AttackID: "lateral-psexec", Name: "PsExec to file server", AttackerIP: "10.0.3.101", TargetIPs: []string{"10.0.1.21"}, Delay: 20},
			},
		},
		{
			ID:              uuid.New().String(),
			Name:            "B4 — Data Exfiltration",
			Description:     "Large-scale sensitive data exfiltration to external server after internal recon",
			Category:        "exfiltration",
			MitreTechniques: []string{"T1041", "T1048", "T1046"},
			DurationSecs:    360,
			ExpectedAlerts:  []string{"Data Exfiltration Detected", "Anomalous Outbound Transfer", "Large Upload"},
			Steps: []ScenarioStep{
				{AttackID: "recon-service-enum", Name: "Enumerate shares", AttackerIP: "10.0.3.101", TargetIPs: []string{"10.0.1.21"}, Delay: 0},
				{AttackID: "exfil-http", Name: "Exfil via HTTPS", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 60, Params: map[string]string{"data_mb": "200"}},
				{AttackID: "c2-dns-tunnel", Name: "DNS tunnel backup exfil", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 30},
			},
		},
		{
			ID:              uuid.New().String(),
			Name:            "B5 — Ransomware Campaign",
			Description:     "Full ransomware attack: initial access, lateral movement, file encryption across network",
			Category:        "ransomware",
			MitreTechniques: []string{"T1486", "T1021.002", "T1110.001"},
			DurationSecs:    600,
			ExpectedAlerts:  []string{"Ransomware Activity", "Mass File Modification", "Lateral Movement", "C2 Beaconing"},
			Steps: []ScenarioStep{
				{AttackID: "auth-bruteforce-rdp", Name: "RDP brute-force entry", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 0},
				{AttackID: "c2-beaconing", Name: "Establish C2", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 60, Params: map[string]string{"count": "3"}},
				{AttackID: "lateral-smb", Name: "Spread laterally", AttackerIP: "10.0.3.101", TargetIPs: []string{"10.0.1.21", "10.0.3.102"}, Delay: 90},
				{AttackID: "exfil-http", Name: "Pre-encryption exfil", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 60, Params: map[string]string{"data_mb": "50"}},
			},
		},
		{
			ID:              uuid.New().String(),
			Name:            "B6 — DNS Tunneling (C2)",
			Description:     "Covert command-and-control using DNS TXT records to tunnel data",
			Category:        "dns_tunnel",
			MitreTechniques: []string{"T1071.004", "T1568.002"},
			DurationSecs:    240,
			ExpectedAlerts:  []string{"DNS Tunneling Detected", "High Volume DNS Queries", "Anomalous DNS TXT Records"},
			Steps: []ScenarioStep{
				{AttackID: "c2-dns-tunnel", Name: "DNS C2 tunnel", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 0, Params: map[string]string{"domain": "c2.tunnel.example", "count": "50"}},
				{AttackID: "c2-dga", Name: "DGA fallback", AttackerIP: "198.51.100.100", TargetIPs: []string{"10.0.3.101"}, Delay: 60, Params: map[string]string{"count": "30"}},
			},
		},
	}
}

// getTestRunsDB returns all test runs from SQLite (with optional status filter).
func getTestRunsDB(statusFilter string) ([]*TestRun, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getTestRunsDB filter=%s", statusFilter)

	query := `SELECT id, scenario_id, scenario_name, status, started_at, completed_at, duration_secs, attacker_ip, target_ips, created_at FROM test_runs`
	var args []interface{}
	if statusFilter != "" {
		query += " WHERE status=?"
		args = append(args, statusFilter)
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := GlobalDB.Query(query, args...)
	if err != nil {
		logError("getTestRunsDB query: %v", err)
		return nil, err
	}
	defer rows.Close()

	var runs []*TestRun
	for rows.Next() {
		var run TestRun
		var targetIPsJSON, createdAtStr string
		var startedAtStr, completedAtStr *string
		var durationSecs *int
		if err = rows.Scan(&run.ID, &run.ScenarioID, &run.ScenarioName, &run.Status,
			&startedAtStr, &completedAtStr, &durationSecs,
			&run.AttackerIP, &targetIPsJSON, &createdAtStr); err != nil {
			logError("getTestRunsDB scan: %v", err)
			continue
		}
		if startedAtStr != nil {
			t, _ := parseTimeStr(*startedAtStr)
			run.StartedAt = &t
		}
		if completedAtStr != nil {
			t, _ := parseTimeStr(*completedAtStr)
			run.CompletedAt = &t
		}
		if durationSecs != nil {
			run.DurationSecs = *durationSecs
		}
		run.CreatedAt, _ = parseTimeStr(createdAtStr)
		json.Unmarshal([]byte(targetIPsJSON), &run.TargetIPs)
		runs = append(runs, &run)
	}

	logInfo("Return from getTestRunsDB count=%d", len(runs))
	return runs, nil
}

// getTestRunDB returns a single test run by ID.
func getTestRunDB(runID string) (*TestRun, error) {
	defer panicHandler(traceFunc(), nil)

	var run TestRun
	var targetIPsJSON, createdAtStr string
	var startedAtStr, completedAtStr *string
	var durationSecs *int
	err := GlobalDB.QueryRow(`
		SELECT id, scenario_id, scenario_name, status, started_at, completed_at, duration_secs, attacker_ip, target_ips, created_at
		FROM test_runs WHERE id=?`, runID).
		Scan(&run.ID, &run.ScenarioID, &run.ScenarioName, &run.Status,
			&startedAtStr, &completedAtStr, &durationSecs,
			&run.AttackerIP, &targetIPsJSON, &createdAtStr)
	if err != nil {
		return nil, err
	}
	if startedAtStr != nil {
		t, _ := parseTimeStr(*startedAtStr)
		run.StartedAt = &t
	}
	if completedAtStr != nil {
		t, _ := parseTimeStr(*completedAtStr)
		run.CompletedAt = &t
	}
	if durationSecs != nil {
		run.DurationSecs = *durationSecs
	}
	run.CreatedAt, _ = parseTimeStr(createdAtStr)
	json.Unmarshal([]byte(targetIPsJSON), &run.TargetIPs)
	return &run, nil
}

// getRunEventsDB returns telemetry events for a given run ID.
func getRunEventsDB(runID string) ([]map[string]interface{}, error) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering getRunEventsDB runID=%s", runID)

	rows, err := GlobalDB.Query(`
		SELECT id, event_time, event_type, source_device, source_ip, dest_ip, protocol, payload
		FROM run_events WHERE run_id=? ORDER BY event_time DESC LIMIT 500`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var id int64
		var eventTimeStr string
		var eventType, sourceDevice, sourceIP, destIP, protocol, payloadStr string
		rows.Scan(&id, &eventTimeStr, &eventType, &sourceDevice, &sourceIP, &destIP, &protocol, &payloadStr)
		eventTime, _ := parseTimeStr(eventTimeStr)
		event := map[string]interface{}{
			"id":            id,
			"event_time":    eventTime,
			"event_type":    eventType,
			"source_device": sourceDevice,
			"source_ip":     sourceIP,
			"dest_ip":       destIP,
			"protocol":      protocol,
			"payload":       json.RawMessage(payloadStr),
		}
		events = append(events, event)
	}
	logInfo("Return from getRunEventsDB count=%d", len(events))
	return events, nil
}

// DashboardStats is the summary for the main dashboard.
type DashboardStats struct {
	TotalRuns   int    `json:"total_runs"`
	RunsToday   int    `json:"runs_today"`
	TotalAlerts int    `json:"total_alerts"`
	ActiveRuns  int    `json:"active_runs"`
	TopScenario string `json:"top_scenario"`
	DeviceCount int    `json:"device_count"`
}

// getDashboardStats returns aggregate statistics for the dashboard.
func getDashboardStats() DashboardStats {
	defer panicHandler(traceFunc(), nil)
	var stats DashboardStats

	GlobalDB.QueryRow(`SELECT COUNT(*) FROM test_runs`).Scan(&stats.TotalRuns)
	GlobalDB.QueryRow(`SELECT COUNT(*) FROM test_runs WHERE started_at >= date('now')`).Scan(&stats.RunsToday)
	GlobalDB.QueryRow(`SELECT COUNT(*) FROM ndr_alerts`).Scan(&stats.TotalAlerts)

	GlobalRunMapLock.RLock()
	for _, run := range GlobalRunMap {
		if run.Status == "running" {
			stats.ActiveRuns++
		}
	}
	GlobalRunMapLock.RUnlock()

	stats.DeviceCount = len(GlobalTopologyMap)

	var topScenario string
	GlobalDB.QueryRow(`SELECT scenario_name FROM test_runs GROUP BY scenario_name ORDER BY COUNT(*) DESC LIMIT 1`).Scan(&topScenario)
	stats.TopScenario = topScenario

	return stats
}

// validateScenario checks that all attack IDs in the scenario exist.
func validateScenario(def *ScenarioDefinition) error {
	if def.Name == "" {
		return fmt.Errorf("scenario name is required")
	}
	for idx, step := range def.Steps {
		if lookupAttack(step.AttackID) == nil {
			return fmt.Errorf("step %d: unknown attack_id '%s'", idx+1, step.AttackID)
		}
	}
	return nil
}
