package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Initialize metadata collector
	collector := NewMetadataCollector()

	// Initialize database in current directory
	dataDir := "data" // Simple subdirectory in current working directory
	fmt.Printf("Initializing database in: %s\n", dataDir)

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
					comm := string(bytes.TrimRight(evt.Comm[:], "\x00"))
					fmt.Printf("\nProcess %d: %s (PID: %d)\n", count, comm, evt.PID)

					// Start metadata collection
					collector.CollectProcessInfo(evt.PID)
					time.Sleep(10 * time.Millisecond)

					info := collector.GetProcessInfo(evt.PID)
					if info == nil {
						fmt.Printf("Warning: No metadata collected for PID %d\n", evt.PID)
						info = &ProcessInfo{
							PID:  evt.PID,
							Comm: comm,
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

					if err := db.InsertProcess(dbRecord); err != nil {
						fmt.Printf("\nError inserting process record: %v\n", err)
					}
				}(event, processCount)

			case EventExit:
				fmt.Printf("- ") // Visual indicator of process exit
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
