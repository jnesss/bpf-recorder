package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Initialize metadata collector
	collector := NewMetadataCollector()

	// Initialize BPF
	reader, cleanup, err := InitBPF()
	if err != nil {
		fmt.Printf("Failed to initialize BPF: %v\n", err)
		os.Exit(1)
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Initialize database with proper permissions
	db, err := initDatabaseWithUser()
	if err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Start web server in background
	go func() {
		if err := startWebServer(db); err != nil {
			fmt.Printf("Web server error: %v\n", err)
		}
	}()
	fmt.Println("Web interface available at http://localhost:8080")

	// Only start BPF monitoring if we have a reader (not on Mac)
	if reader != nil {
		// Create buffered channel for events
		eventChan := make(chan Event, 1000) // Buffer size to handle bursts

		// Start event processor and BPF reader
		go startEventProcessor(eventChan, collector, db)
		go startBPFReader(reader, eventChan)

		fmt.Println("Process monitoring started... Press Ctrl+C to stop")
	}

	// Set up signal handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	<-sig
	fmt.Println("Shutting down...")
}

func processExecEvent(evt Event, count int, collector *MetadataCollector, db *DB) {
	// Each collection gets its own completion channel
	done := collector.CollectProcessInfo(evt.PID)
	info := <-done // We're guaranteed to get the right process's info

	if info == nil {
		info = &ProcessInfo{
			PID:  evt.PID,
			Comm: string(bytes.TrimRight(evt.Comm[:], "\x00")),
		}
	}

	// Merge event data with collected process info
	ppid := info.PPID
	if evt.PPID > 0 {
		ppid = evt.PPID
	}

	parentComm := info.ParentComm
	if len(bytes.TrimRight(evt.ParentComm[:], "\x00")) > 0 {
		parentComm = string(bytes.TrimRight(evt.ParentComm[:], "\x00"))
	}

	username := info.Username
	if evt.UID > 0 && username == "" {
		if u, err := user.LookupId(fmt.Sprintf("%d", evt.UID)); err == nil {
			username = u.Username
		}
	}

	workingDir := info.WorkingDir
	if len(bytes.TrimRight(evt.CWD[:], "\x00")) > 0 {
		workingDir = string(bytes.TrimRight(evt.CWD[:], "\x00"))
	}

	// Placeholder for command line - empty for now
	cmdLine := "" // Will be implemented later

	envJSON, _ := json.Marshal(info.Environment)
	dbRecord := &ProcessRecord{
		Timestamp:   time.Now(),
		PID:         info.PID,
		PPID:        ppid,
		Comm:        info.Comm,
		CmdLine:     cmdLine,
		ExePath:     info.ExePath,
		WorkingDir:  workingDir,
		Username:    username,
		ParentComm:  parentComm,
		Environment: string(envJSON),
		ContainerID: info.ContainerID,
		UID:         fmt.Sprintf("%d", evt.UID),
		GID:         fmt.Sprintf("%d", evt.GID),
	}

	// Drop privileges for database operations
	if err := dropPrivileges(); err != nil {
		fmt.Printf("\nWarning: Failed to drop privileges: %v\n", err)
	}

	if err := db.InsertProcess(dbRecord); err != nil {
		fmt.Printf("\nError inserting process record: %v\n", err)
	} else {
		fmt.Print(".")
		if count%100 == 0 {
			fmt.Printf(" [%d]\n", count)
		}
	}
}

func startEventProcessor(eventChan chan Event, collector *MetadataCollector, db *DB) {
	fmt.Println("Starting event processor...")
	processCount := 0
	for event := range eventChan {
		switch event.EventType {
		case EventExec:
			processCount++
			go processExecEvent(event, processCount, collector, db)
		case EventExit:
			collector.RemoveProcess(event.PID)
		}
	}
}

func startBPFReader(reader PerfReader, eventChan chan Event) {
	var event Event
	for {
		record, err := reader.Read()
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				close(eventChan)
				return
			}
			fmt.Printf("Error reading perf buffer: %v\n", err)
			continue
		}

		if record.LostSamples != 0 {
			fmt.Printf("Lost %d samples\n", record.LostSamples)
			continue
		}

		// Parse event data
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			fmt.Printf("Error parsing event: %v\n", err)
			continue
		}

		// Add this debug code:
		if event.EventType == EventExec {
			// Try to read command line from map
			if cmdlinesMapFD != 0 {
				// Create a key and value for reading from the map
				key := event.PID
				var value [256]byte

				// Lookup the command line from the map
				err := objs.Cmdlines.Lookup(&key, &value)
				if err != nil {
					fmt.Printf("Failed to read command line for PID %d: %v\n", key, err)
				} else {
					cmdLine := strings.TrimRight(string(value[:]), "\x00")
					fmt.Printf("PID %d command line: %s\n", key, cmdLine)
				}

				// Also print the executable for comparison
				fmt.Printf("PID %d executable: %s\n", key, strings.TrimRight(string(event.Filename[:]), "\x00"))
			}
		}

		// Send event for processing
		eventChan <- event
	}
}

func initDatabaseWithUser() (*DB, error) {
	dataDir := "data"

	// Drop privileges before doing anything with the database
	if err := dropPrivileges(); err != nil {
		return nil, fmt.Errorf("failed to drop privileges: %v", err)
	}

	// Create database as unprivileged user - they can create their own directory
	return NewDB(dataDir)
}
