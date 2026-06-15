// Package main — api_server.go
// Gin HTTP server setup, route registration, CORS, and WebSocket hub.
package main

import (
	"encoding/json"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// GlobalWSHub is the WebSocket broadcast hub for live telemetry.
var GlobalWSHub = newWSHub()

// wsUpgrader upgrades HTTP connections to WebSocket.
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin: func(req *http.Request) bool {
		return true // allow all origins in dev
	},
}

// WSHub manages connected WebSocket clients.
type WSHub struct {
	clients   map[*websocket.Conn]bool
	broadcast chan []byte
	register  chan *websocket.Conn
	unregister chan *websocket.Conn
}

// newWSHub creates a new WebSocket hub.
func newWSHub() *WSHub {
	return &WSHub{
		clients:    map[*websocket.Conn]bool{},
		broadcast:  make(chan []byte, 512),
		register:   make(chan *websocket.Conn, 64),
		unregister: make(chan *websocket.Conn, 64),
	}
}

// run starts the hub dispatch loop.
func (hub *WSHub) run() {
	defer panicHandler(traceFunc(), nil)
	for {
		select {
		case conn := <-hub.register:
			hub.clients[conn] = true
		case conn := <-hub.unregister:
			if _, ok := hub.clients[conn]; ok {
				delete(hub.clients, conn)
				conn.Close()
			}
		case msg := <-hub.broadcast:
			for conn := range hub.clients {
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					hub.unregister <- conn
				}
			}
		}
	}
}

// broadcastEvent publishes a JSON event to all connected WebSocket clients.
func broadcastEvent(eventType string, payload interface{}) {
	data, err := json.Marshal(map[string]interface{}{
		"type":    eventType,
		"payload": payload,
		"ts":      time.Now().UnixMilli(),
	})
	if err != nil {
		return
	}
	select {
	case GlobalWSHub.broadcast <- data:
	default:
	}
}

// startAPIServer initialises the Gin engine and starts the HTTP listener.
func startAPIServer() {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering startAPIServer")

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(ginLogger(), ginRecovery(), corsMiddleware())

	// WebSocket hub
	go GlobalWSHub.run()

	// Static files (Angular build)
	router.Static("/static", "./netsim-ui/dist/netsim-ui/browser")
	router.StaticFile("/", "./netsim-ui/dist/netsim-ui/browser/index.html")
	router.NoRoute(func(ginCtx *gin.Context) {
		ginCtx.File("./netsim-ui/dist/netsim-ui/browser/index.html")
	})

	// WebSocket
	router.GET("/ws", handleWebSocket)

	// Health
	router.GET("/health", func(ginCtx *gin.Context) {
		ginCtx.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now()})
	})

	// API v1
	api := router.Group("/api/v1")
	{
		// Dashboard
		api.GET("/dashboard", handleGetDashboard)

		// Topology
		api.GET("/topology/devices", handleListDevices)
		api.GET("/topology/devices/:id", handleGetDevice)
		api.POST("/topology/devices", handleCreateDevice)
		api.PUT("/topology/devices/:id", handleUpdateDevice)
		api.DELETE("/topology/devices/:id", handleDeleteDevice)
		api.GET("/topology/graph", handleTopologyGraph)
		api.GET("/topology/summary", handleTopologySummary)

		// Attacks
		api.GET("/attacks", handleListAttacks)
		api.GET("/attacks/history", handleGetAttackHistory)
		api.GET("/attacks/:id", handleGetAttack)
		api.POST("/attacks/execute", handleExecuteAttack)

		// Scenarios
		api.GET("/scenarios", handleListScenarios)
		api.GET("/scenarios/:id", handleGetScenario)
		api.POST("/scenarios", handleCreateScenario)
		api.PUT("/scenarios/:id", handleUpdateScenario)
		api.DELETE("/scenarios/:id", handleDeleteScenario)

		// Test Runs
		api.GET("/runs", handleListRuns)
		api.GET("/runs/:id", handleGetRun)
		api.POST("/runs", handleStartRun)
		api.POST("/runs/:id/abort", handleAbortRun)
		api.GET("/runs/:id/events", handleGetRunEvents)

		// NDR Alert Ingestion (called by NDR agent or webhook)
		api.POST("/alerts/ingest", handleIngestAlert)

		// Telemetry viewer
		api.GET("/telemetry/syslog", handleGetSyslogTelemetry)
		api.GET("/telemetry/flows", handleGetFlowTelemetry)
		api.GET("/telemetry/pcap", handleGetPCAPFiles)
		api.GET("/telemetry/pcap/:filename", handleDownloadPCAP)
		api.GET("/telemetry/stats", handleGetTelemetryStats)
		api.GET("/telemetry/listeners", handleGetListenerStatus)

		// Audit log
		api.GET("/audit", handleGetAuditLog)

		// SNMP agent
		api.GET("/snmp/status", handleGetSNMPStatus)
		api.POST("/snmp/rebuild", handleRebuildSNMPTree)
	}

	port := configString("server.port", "8090")
	serverAddr := ":" + port
	logInfo("startAPIServer listening on %s", serverAddr)

	debug.SetGCPercent(40)

	if err := router.Run(serverAddr); err != nil {
		logError("startAPIServer Run: %v", err)
	}
	logInfo("Return from startAPIServer")
}

// handleWebSocket upgrades the connection and registers it with the hub.
func handleWebSocket(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	conn, err := wsUpgrader.Upgrade(ginCtx.Writer, ginCtx.Request, nil)
	if err != nil {
		logError("handleWebSocket upgrade: %v", err)
		return
	}
	GlobalWSHub.register <- conn
	go func() {
		defer func() { GlobalWSHub.unregister <- conn }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}

// ginLogger returns a Gin middleware that logs each request.
func ginLogger() gin.HandlerFunc {
	return func(ginCtx *gin.Context) {
		start := time.Now()
		ginCtx.Next()
		logInfo("HTTP %s %s %d %v", ginCtx.Request.Method, ginCtx.Request.URL.Path, ginCtx.Writer.Status(), time.Since(start))
	}
}

// ginRecovery returns a Gin middleware that recovers from panics.
func ginRecovery() gin.HandlerFunc {
	return func(ginCtx *gin.Context) {
		defer func() {
			if rec := recover(); rec != nil {
				logError("ginRecovery: panic %v\n%s", rec, debug.Stack())
				ginCtx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
		}()
		ginCtx.Next()
	}
}

// corsMiddleware adds CORS headers for development.
func corsMiddleware() gin.HandlerFunc {
	return func(ginCtx *gin.Context) {
		ginCtx.Header("Access-Control-Allow-Origin", "*")
		ginCtx.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ginCtx.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if ginCtx.Request.Method == "OPTIONS" {
			ginCtx.AbortWithStatus(http.StatusNoContent)
			return
		}
		ginCtx.Next()
	}
}

// handleGetDashboard returns aggregate dashboard statistics.
func handleGetDashboard(ginCtx *gin.Context) {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering handleGetDashboard")
	stats := getDashboardStats()
	ginCtx.JSON(http.StatusOK, stats)
	logInfo("Return from handleGetDashboard")
}
