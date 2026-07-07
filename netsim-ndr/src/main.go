// Package main — main.go
// NDR Test Environment Simulator server entry point.
// Initialises config, database, topology, telemetry emitters, and starts the HTTP API server.
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime/debug"
	"time"
)

const serverName = "netsim-ndr"

func main() {
	defer panicHandler(traceFunc(), nil)

	// Parse command-line flags before anything else
	streamHost := flag.String("stream-host", "", "IP address to stream raw PCAP packets to (e.g. 10.0.0.5)")
	streamPort := flag.Int("stream-port", 0, "UDP port to stream raw PCAP packets to (e.g. 9999)")
	flag.Parse()

	initLogging()
	logInfo("Starting %s", serverName)

	debug.SetGCPercent(40)
	rand.Seed(time.Now().UnixNano())

	GlobalServerStartTime = time.Now()

	// Initialise packet streamer if both flags provided
	if *streamHost != "" && *streamPort > 0 {
		if err := initPacketStreamer(*streamHost, *streamPort); err != nil {
			logWarn("main: packet streamer not started: %v", err)
		} else {
			logInfo("main: streaming packets to %s:%d", *streamHost, *streamPort)
		}
	}

	startNetSimServer()
}

// startNetSimServer is the primary entry function that wires up all components.
func startNetSimServer() {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering startNetSimServer")

	// 1. Load configuration
	if err := loadConfiguration(serverName); err != nil {
		logError("startNetSimServer config: %v", err)
		fmt.Fprintf(os.Stderr, "FATAL: cannot load configuration: %v\n", err)
		os.Exit(1)
	}

	// 2. Open SQLite database
	if err := initDatabase(); err != nil {
		logError("startNetSimServer database: %v", err)
		fmt.Fprintf(os.Stderr, "FATAL: cannot open database: %v\n", err)
		os.Exit(1)
	}

	// 3. Ensure output directories exist
	if err := ensureDir(configString("output.pcap.dir", "output/pcap")); err != nil {
		log.Printf("WARN: cannot create pcap dir: %v", err)
	}
	if err := ensureDir(configString("output.logs.dir", "logs")); err != nil {
		log.Printf("WARN: cannot create logs dir: %v", err)
	}

	// 4. Load and seed the 24-device topology
	if err := loadTopology(); err != nil {
		logError("startNetSimServer loadTopology: %v", err)
	}
	if err := seedDefaultTopology(); err != nil {
		logError("startNetSimServer seedTopology: %v", err)
	}

	// 5. Seed built-in scenarios
	loadBuiltInScenarios()

	// 6. Initialise attack registry (34 attacks)
	initAttackRegistry()

	// 7. Initialise telemetry emitters (non-fatal if NDR agent not reachable)
	if err := initSyslogEmitter(); err != nil {
		logWarn("startNetSimServer syslog emitter not connected: %v", err)
	}
	if err := initFlowExporters(); err != nil {
		logWarn("startNetSimServer flow exporters not connected: %v", err)
	}
	if err := initPCAPWriter(); err != nil {
		logWarn("startNetSimServer pcap writer: %v", err)
	}
	if err := initLogWriter(); err != nil {
		logWarn("startNetSimServer log writer: %v", err)
	}

	// 7b. Initialise real packet sender (Option A — on-wire connections)
	initRealPacketSender()

	// 7c. Start telemetry listeners (passive collection from real devices)
	if err := initTelemetryListeners(); err != nil {
		logWarn("startNetSimServer telemetry listeners: %v", err)
	}

	// 8. Start SNMP agent (non-fatal — logs error if port unavailable)
	go initSNMPAgent()

	// 9. Start HTTP API server (blocks)
	logInfo("startNetSimServer all components ready — starting API server")
	startAPIServer()
	logInfo("Return from startNetSimServer")
}
