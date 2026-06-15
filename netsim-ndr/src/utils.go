// Package main — utils.go
// PanicHandler, logging wrappers, property loader, common helpers.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/magiconair/properties"
)

// GlobalConfig holds all configuration properties loaded at startup.
var GlobalConfig *properties.Properties

// GlobalServerStartTime records when the server started.
var GlobalServerStartTime time.Time

// loadConfiguration reads the properties file for this server.
func loadConfiguration(serverName string) error {
	log.Printf("Entering loadConfiguration serverName=%s", serverName)

	confPath := fmt.Sprintf("conf/%s.properties", serverName)
	props, err := properties.LoadFile(confPath, properties.UTF8)
	if err != nil {
		log.Printf("ERROR loadConfiguration: %v", err)
		return fmt.Errorf("cannot load config %s: %w", confPath, err)
	}
	GlobalConfig = props
	log.Printf("Return from loadConfiguration loaded=%d keys", len(props.Keys()))
	return nil
}

// configString returns a string property with a fallback default.
func configString(key, defaultVal string) string {
	if GlobalConfig == nil {
		return defaultVal
	}
	return GlobalConfig.GetString(key, defaultVal)
}

// configInt returns an int property with a fallback default.
func configInt(key string, defaultVal int) int {
	if GlobalConfig == nil {
		return defaultVal
	}
	return GlobalConfig.GetInt(key, defaultVal)
}

// traceFunc returns a string identifying the calling function for use in PanicHandler.
func traceFunc() string {
	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		return "unknown"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return fmt.Sprintf("%s (%s:%d)", fn.Name(), file, line)
}

// panicHandler recovers from panics, logs the stack trace, and optionally calls a cleanup func.
func panicHandler(location string, cleanup func()) {
	if rec := recover(); rec != nil {
		stack := debug.Stack()
		log.Printf("PANIC recovered at %s: %v\n%s", location, rec, stack)
		if cleanup != nil {
			cleanup()
		}
	}
}

// logInfo logs an informational message.
func logInfo(format string, args ...interface{}) {
	log.Printf("[INFO]  "+format, args...)
}

// logTrace logs a trace/debug message.
func logTrace(format string, args ...interface{}) {
	log.Printf("[TRACE] "+format, args...)
}

// logError logs an error message.
func logError(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// logWarn logs a warning message.
func logWarn(format string, args ...interface{}) {
	log.Printf("[WARN]  "+format, args...)
}

// initLogging configures the standard logger to write to stdout with timestamps.
func initLogging() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

// randomIP returns a random IP address within a given CIDR.
func randomIP(cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "10.0.0.1"
	}
	ip := ipNet.IP
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return ip.String()
	}
	randHost := rand.Intn(1 << uint(hostBits))
	ipInt := binary.BigEndian.Uint32(ip.To4())
	ipInt = (ipInt &^ uint32((1<<uint(hostBits))-1)) | uint32(randHost)
	result := make(net.IP, 4)
	binary.BigEndian.PutUint32(result, ipInt)
	return result.String()
}

// ipToUint32 converts an IPv4 address string to uint32.
func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// randomPort returns a random ephemeral port number.
func randomPort() uint16 {
	return uint16(49152 + rand.Intn(16383))
}

// jsonResponse wraps a value in a generic JSON map for simple success responses.
func jsonResponseMap(key, value string) map[string]string {
	return map[string]string{key: value}
}

// ensureDir creates a directory if it doesn't exist.
func ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// nowMillis returns the current Unix timestamp in milliseconds.
func nowMillis() int64 {
	return time.Now().UnixMilli()
}

// parseTimeStr parses a time string stored by SQLite (RFC3339 or SQLite default formats).
func parseTimeStr(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time: %q", s)
}
