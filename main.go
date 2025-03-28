package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Initialize metadata collector
	collector := NewMetadataCollector()

	// Initialize database
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Failed to get home directory: %v\n", err)
		os.Exit(1)
	}
	dataDir := filepath.Join(homeDir, ".bpf-recorder")

	db, err := NewDB(dataDir)
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

	fmt.Println("Process monitoring started... Press Ctrl+C to stop")

	// Process events
	go func() {
		var event Event

		for {
			record, err := reader.Read()
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
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

			// Handle different event types
			switch event.EventType {
			case EventExec:
				// Start metadata collection in background
				collector.CollectProcessInfo(event.PID)

				// Give the collector a moment to gather data
				time.Sleep(10 * time.Millisecond)

				// Get collected metadata
				info := collector.GetProcessInfo(event.PID)
				if info == nil {
					// If metadata collection failed, create minimal record
					info = &ProcessInfo{
						PID:  event.PID,
						Comm: string(bytes.TrimRight(event.Comm[:], "\x00")),
					}
				}

				// Convert environment to JSON for storage
				envJSON, _ := json.Marshal(info.Environment)

				// Create database record
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
				}

				// Insert into database
				if err := db.InsertProcess(dbRecord); err != nil {
					fmt.Printf("Failed to insert process record: %v\n", err)
				}

			case EventExit:
				// Clean up metadata for exited process
				collector.RemoveProcess(event.PID)
			}
		}
	}()

	// Wait for signal
	<-sig
	fmt.Println("Shutting down...")
}
