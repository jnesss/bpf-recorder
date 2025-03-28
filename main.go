package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Set up logging
	logger := log.New(os.Stdout, "", log.LstdFlags)

	// Initialize BPF (platform-specific)
	reader, cleanup, err := InitBPF()
	if err != nil {
		logger.Fatalf("Failed to initialize BPF: %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Set up signal handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	logger.Println("Process monitoring started... Press Ctrl+C to stop")

	// Process events
	go func() {
		var event Event
		eventCount := 0
		lastEventTime := time.Now()

		for {
			// Add heartbeat to show loop is running
			if time.Since(lastEventTime) > 10*time.Second {
				logger.Printf("Still monitoring... (processed %d events)", eventCount)
				lastEventTime = time.Now()
			}

			record, err := reader.Read()
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					return
				}
				logger.Printf("Error reading perf buffer: %v", err)
				continue
			}

			if record.LostSamples != 0 {
				logger.Printf("Lost %d samples", record.LostSamples)
				continue
			}

			// Parse event data
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				logger.Printf("Error parsing event: %v", err)
				continue
			}

			// Convert C string to Go string
			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

			// Handle different event types
			switch event.EventType {
			case EventExec:
				filename := string(bytes.TrimRight(event.Filename[:], "\x00"))
				ppid := GetParentPID(event.PID)
				args := GetCommandLineArgs(event.PID)

				if len(args) == 0 {
					args = []string{filename}
				}

				cmdLine := strings.Join(args, " ")
				processTreeStr := GetProcessTree(event.PID, comm)
				StoreProcess(event.PID, processTreeStr)

				logger.Printf("EXEC PID: %d, PPID: %d, Command: %s, Args: %s, Tree: %s",
					event.PID, ppid, comm, cmdLine, processTreeStr)

			case EventExit:
				ppid := GetParentPID(event.PID)
				processTreeStr := GetProcessTree(event.PID, comm)

				logger.Printf("EXIT PID: %d, PPID: %d, Command: %s, Exit Code: %d, Tree: %s",
					event.PID, ppid, comm, event.ExitCode, processTreeStr)

				RemoveProcess(event.PID)

			default:
				logger.Printf("Unknown event type: %d", event.EventType)
			}

			eventCount++
			lastEventTime = time.Now()
		}
	}()

	// Wait for signal
	<-sig
	logger.Println("Shutting down...")
}
