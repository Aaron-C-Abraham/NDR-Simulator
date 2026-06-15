// Package main — telemetry_api.go
// HTTP API handlers for live telemetry viewing, reports, MITRE coverage, and audit log.
package main

import (
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ─── Telemetry Handlers ───────────────────────────────────────────────────────

func handleGetSyslogTelemetry(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetSyslogTelemetry")

	limitStr := ginCtx.DefaultQuery("limit", "200")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	deviceFilter := ginCtx.Query("device")
	formatFilter := ginCtx.Query("format")

	messages, err := getRecentSyslogMessages(limit, deviceFilter, formatFilter)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if messages == nil {
		messages = []StoredSyslogMessage{}
	}
	ginCtx.JSON(http.StatusOK, gin.H{"messages": messages, "total": len(messages)})
	logInfo("Return from handleGetSyslogTelemetry count=%d", len(messages))
}

func handleGetFlowTelemetry(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetFlowTelemetry")

	limitStr := ginCtx.DefaultQuery("limit", "200")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	srcFilter := ginCtx.Query("src")
	dstFilter := ginCtx.Query("dst")
	flowTypeFilter := ginCtx.Query("type")

	flows, err := getRecentFlowRecords(limit, srcFilter, dstFilter, flowTypeFilter)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if flows == nil {
		flows = []StoredFlowRecord{}
	}
	ginCtx.JSON(http.StatusOK, gin.H{"flows": flows, "total": len(flows)})
	logInfo("Return from handleGetFlowTelemetry count=%d", len(flows))
}

func handleGetPCAPFiles(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetPCAPFiles")

	files, err := getPCAPFiles()
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if files == nil {
		files = []PCAPFileInfo{}
	}
	ginCtx.JSON(http.StatusOK, gin.H{"files": files, "total": len(files)})
	logInfo("Return from handleGetPCAPFiles count=%d", len(files))
}

func handleDownloadPCAP(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	filename := ginCtx.Param("filename")
	logInfo("Entering handleDownloadPCAP filename=%s", filename)

	// Prevent directory traversal
	safe := filepath.Base(filename)
	pcapDir := configString("output.pcap.dir", "output/pcap")
	fullPath := filepath.Join(pcapDir, safe)

	ginCtx.Header("Content-Disposition", "attachment; filename="+safe)
	ginCtx.File(fullPath)
	logInfo("Return from handleDownloadPCAP filename=%s", safe)
}

func handleGetTelemetryStats(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetTelemetryStats")
	stats := getTelemetryStats()
	ginCtx.JSON(http.StatusOK, stats)
	logInfo("Return from handleGetTelemetryStats")
}

// ─── Audit Log Handler ────────────────────────────────────────────────────────

func handleGetAuditLog(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetAuditLog")

	limitStr := ginCtx.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	entries, err := getAuditLogEntries(limit)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}
	ginCtx.JSON(http.StatusOK, gin.H{"entries": entries, "total": len(entries)})
	logInfo("Return from handleGetAuditLog count=%d", len(entries))
}

// ─── Listener Status Handler ──────────────────────────────────────────────────

func handleGetListenerStatus(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetListenerStatus")

	statuses := getListenerStatuses()
	ginCtx.JSON(http.StatusOK, gin.H{"listeners": statuses, "total": len(statuses)})
	logInfo("Return from handleGetListenerStatus count=%d", len(statuses))
}
