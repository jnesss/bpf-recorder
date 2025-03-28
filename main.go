package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Initialize metadata collector
	collector := NewMetadataCollector()

	// Initialize database with proper permissions
	db, err := initDatabaseWithUser()
	if err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Initialize BPF
	reader, cleanup, err := InitBPF()
	if err != nil {
		fmt.Printf("Failed to initialize BPF: %v\n", err)
		os.Exit(1)
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Set up signal handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Create buffered channel for events
	eventChan := make(chan Event, 1000) // Buffer size to handle bursts

	// Start event processor
	go func() {
		fmt.Println("Starting event processor...")
		processCount := 0
		for event := range eventChan {
			switch event.EventType {
			case EventExec:
				processCount++
				go func(evt Event, count int) {
					// Each collection gets its own completion channel
					done := collector.CollectProcessInfo(evt.PID)
					info := <-done // We're guaranteed to get the right process's info

					if info == nil {
						info = &ProcessInfo{
							PID:  evt.PID,
							Comm: string(bytes.TrimRight(evt.Comm[:], "\x00")),
						}
					}

					envJSON, _ := json.Marshal(info.Environment)
					dbRecord := &ProcessRecord{
						Timestamp:   time.Now(),
						PID:         info.PID,
						PPID:        info.PPID,
						Comm:        info.Comm,
						CmdLine:     strings.Join(info.CmdLine, " "),
						ExePath:     info.ExePath,
						WorkingDir:  info.WorkingDir,
						Username:    info.Username,
						ParentComm:  info.ParentComm,
						Environment: string(envJSON),
						ContainerID: info.ContainerID,
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
				}(event, processCount)

			case EventExit:
				// Just remove from collector, no logging needed
				collector.RemoveProcess(event.PID)
			}
		}
	}()

	fmt.Println("Process monitoring started... Press Ctrl+C to stop")

	// Start BPF event reader
	go func() {
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

			// Send event for processing
			eventChan <- event
		}
	}()

	// Wait for signal
	<-sig
	fmt.Println("Shutting down...")
}

func initDatabaseWithUser() (*DB, error) {
	dataDir := "data"

	// Get original user if running under sudo
	u, err := getOriginalUser()
	if err != nil {
		fmt.Printf("Warning: Could not get original user: %v\n", err)
	} else {
		// Create data directory with proper ownership
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)

		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create data directory: %v", err)
		}
		if err := os.Chown(dataDir, uid, gid); err != nil {
			return nil, fmt.Errorf("failed to change data directory ownership: %v", err)
		}
	}

	// Open database
	db, err := NewDB(dataDir)
	if err != nil {
		return nil, err
	}

	return db, nil
}
