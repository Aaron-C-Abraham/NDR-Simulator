// Package main — db.go
// SQLite database connection and schema initialization.
package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// GlobalDB is the shared SQLite connection.
var GlobalDB *sql.DB

// initDatabase opens the SQLite file and ensures the schema exists.
func initDatabase() error {
	logInfo("Entering initDatabase")

	dbPath := configString("db.path", "netsim-ndr.db")
	logTrace("db.path=%s", dbPath)

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		logError("initDatabase open: %v", err)
		return err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err = db.Ping(); err != nil {
		logError("initDatabase ping: %v", err)
		return fmt.Errorf("cannot open SQLite database %s: %w", dbPath, err)
	}

	GlobalDB = db

	if err = runSchemaMigration(); err != nil {
		logError("initDatabase migration: %v", err)
		return err
	}

	logInfo("Return from initDatabase path=%s", dbPath)
	return nil
}

// runSchemaMigration executes the embedded DDL statements.
func runSchemaMigration() error {
	logInfo("Entering runSchemaMigration")
	ddls := []string{
		`CREATE TABLE IF NOT EXISTS devices (
			id          TEXT NOT NULL PRIMARY KEY,
			name        TEXT NOT NULL,
			device_type TEXT NOT NULL,
			ip_address  TEXT NOT NULL,
			mac_address TEXT NOT NULL,
			os_type     TEXT NOT NULL,
			vendor      TEXT NOT NULL,
			network_zone TEXT NOT NULL,
			telemetry   TEXT NOT NULL DEFAULT '{}',
			status      TEXT NOT NULL DEFAULT 'active',
			created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
			updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS scenarios (
			id               TEXT NOT NULL PRIMARY KEY,
			name             TEXT NOT NULL,
			description      TEXT NOT NULL,
			category         TEXT NOT NULL,
			mitre_techniques TEXT NOT NULL DEFAULT '[]',
			attack_steps     TEXT NOT NULL DEFAULT '[]',
			expected_alerts  TEXT NOT NULL DEFAULT '[]',
			duration_secs    INTEGER NOT NULL DEFAULT 300,
			created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
			updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS test_runs (
			id              TEXT NOT NULL PRIMARY KEY,
			scenario_id     TEXT NOT NULL,
			scenario_name   TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT 'pending',
			started_at      TEXT,
			completed_at    TEXT,
			duration_secs   INTEGER,
			attacker_ip     TEXT NOT NULL,
			target_ips      TEXT NOT NULL DEFAULT '[]',
			config_snapshot TEXT NOT NULL DEFAULT '{}',
			created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS run_events (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id        TEXT NOT NULL,
			event_time    TEXT NOT NULL,
			event_type    TEXT NOT NULL,
			source_device TEXT,
			source_ip     TEXT,
			dest_ip       TEXT,
			protocol      TEXT,
			payload       TEXT NOT NULL DEFAULT '{}',
			created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS ndr_alerts (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id      TEXT NOT NULL,
			alert_time  TEXT NOT NULL,
			alert_type  TEXT NOT NULL,
			severity    TEXT NOT NULL,
			source_ip   TEXT,
			dest_ip     TEXT,
			mitre_id    TEXT,
			description TEXT,
			raw_payload TEXT NOT NULL DEFAULT '{}',
			created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			actor      TEXT NOT NULL DEFAULT 'system',
			action     TEXT NOT NULL,
			resource   TEXT,
			detail     TEXT,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS syslog_messages (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			device_ip   TEXT NOT NULL DEFAULT '',
			device_name TEXT NOT NULL DEFAULT '',
			format      TEXT NOT NULL DEFAULT 'rfc3164',
			severity    INTEGER NOT NULL DEFAULT 6,
			message     TEXT NOT NULL DEFAULT '',
			raw         TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS flow_records (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			src_ip      TEXT NOT NULL DEFAULT '',
			dst_ip      TEXT NOT NULL DEFAULT '',
			src_port    INTEGER NOT NULL DEFAULT 0,
			dst_port    INTEGER NOT NULL DEFAULT 0,
			protocol    INTEGER NOT NULL DEFAULT 6,
			bytes       INTEGER NOT NULL DEFAULT 0,
			packets     INTEGER NOT NULL DEFAULT 0,
			start_time  TEXT NOT NULL DEFAULT '',
			end_time    TEXT NOT NULL DEFAULT '',
			exporter_ip TEXT NOT NULL DEFAULT '',
			flow_type   TEXT NOT NULL DEFAULT 'netflow9',
			created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS attack_executions (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			attack_id    TEXT NOT NULL,
			attack_name  TEXT NOT NULL,
			category     TEXT NOT NULL,
			attacker_ip  TEXT NOT NULL,
			target_ips   TEXT NOT NULL DEFAULT '[]',
			status       TEXT NOT NULL DEFAULT 'success',
			syslog_count INTEGER NOT NULL DEFAULT 0,
			flow_count   INTEGER NOT NULL DEFAULT 0,
			pcap_files   TEXT NOT NULL DEFAULT '[]',
			error_msg    TEXT NOT NULL DEFAULT '',
			started_at   TEXT NOT NULL,
			completed_at TEXT NOT NULL,
			duration_ms  INTEGER NOT NULL DEFAULT 0,
			created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		)`,
	}
	for _, ddl := range ddls {
		if _, err := GlobalDB.Exec(ddl); err != nil {
			logError("runSchemaMigration exec: %v\nddl: %s", err, ddl[:minInt(len(ddl), 80)])
			return err
		}
	}
	logInfo("Return from runSchemaMigration ok tables=%d", len(ddls))
	return nil
}

// splitSQLStatements splits a SQL file by semicolons (retained for any external schema files).
func splitSQLStatements(sqlText string) []string {
	var statements []string
	var current strings.Builder
	for _, line := range strings.Split(sqlText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			statements = append(statements, current.String())
			current.Reset()
		}
	}
	return statements
}

// writeAuditLog inserts an audit log entry.
func writeAuditLog(actor, action, resource string, detail interface{}) {
	defer panicHandler(traceFunc(), nil)
	detailJSON := "{}"
	if detail != nil {
		if jsonBytes, err := marshalJSON(detail); err == nil {
			detailJSON = string(jsonBytes)
		}
	}
	_, err := GlobalDB.Exec(
		`INSERT INTO audit_log (actor, action, resource, detail) VALUES (?,?,?,?)`,
		actor, action, resource, detailJSON,
	)
	if err != nil {
		logError("writeAuditLog: %v", err)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
