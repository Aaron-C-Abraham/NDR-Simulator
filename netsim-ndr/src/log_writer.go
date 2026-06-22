package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GlobalLogsDir is the output directory for per-run plain-text log files.
var GlobalLogsDir string

// logWriteLocks guards concurrent writes to the same run's log files —
// one mutex per (runID, format) pair, created lazily.
var logWriteLocks sync.Map // map[string]*sync.Mutex

// initLogWriter creates the logs output directory.
func initLogWriter() error {
	defer panicHandler(traceFunc(), nil)
	logInfo("Entering initLogWriter")

	GlobalLogsDir = configString("output.runlogs.dir", "output/logs")
	if err := ensureDir(GlobalLogsDir); err != nil {
		logError("initLogWriter ensureDir: %v", err)
		return err
	}
	logInfo("Return from initLogWriter dir=%s", GlobalLogsDir)
	return nil
}

// writeLogLine appends a single plain-text line to
// output/logs/<runID>/<format>.log, creating the run's log directory and
// file as needed. format should be one of: syslog, netflow, sflow, ipfix.
func writeLogLine(runID, format, line string) error {
	defer panicHandler(traceFunc(), nil)

	if runID == "" || format == "" {
		return nil
	}

	lockKey := format
	lockIface, _ := logWriteLocks.LoadOrStore(lockKey, &sync.Mutex{})
	lock := lockIface.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	path := filepath.Join(GlobalLogsDir, format+".log")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logError("writeLogLine open %s: %v", path, err)
		return err
	}
	defer file.Close()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := fmt.Fprintf(file, "%s run_id=%s %s\n", timestamp, runID, line); err != nil {
		logError("writeLogLine write %s: %v", path, err)
		return err
	}
	return nil
}
