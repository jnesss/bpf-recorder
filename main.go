package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"
)

const (
	DefaultDataDir  = "./data"
	DefaultRulesDir = "./rules"
	DefaultBinsDir  = "./bins"
)

func main() {
	// Parse command line arguments
	dataDir := flag.String("data", DefaultDataDir, "Directory for storing data")
	rulesDir := flag.String("rules", DefaultRulesDir, "Directory for Sigma rules")
	binsDir := flag.String("bins", DefaultBinsDir, "Directory for binary storage")
	binCacheSize := flag.Int("bin-cache-size", 128, "Size of binary cache")
	webOnly := flag.Bool("web-only", false, "Run in web UI only mode without BPF monitoring")
	flag.Parse()

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

	// Initialize binary cache
	binaryCache, err := NewBinaryCache(*binCacheSize, *binsDir)
	if err != nil {
		fmt.Printf("Failed to initialize binary cache: %v\n", err)
		os.Exit(1)
	}

	// Save current privileges
	savedUID := os.Getuid()
	savedGID := os.Getgid()

	// Drop privileges before creating or opening the database
	if err := dropPrivileges(); err != nil {
		fmt.Printf("Failed to drop privileges: %v\n", err)
		os.Exit(1)
	}

	// Initialize database with proper permissions
	db, err := NewDB(*dataDir)
	if err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Restore privileges
	syscall.Setreuid(savedUID, savedUID)
	syscall.Setregid(savedGID, savedGID)

	// Initialize Sigma detector
	sigmaDetector, err := NewSigmaDetector(*rulesDir, db.db)
	if err != nil {
		log.Printf("Warning: Failed to initialize Sigma detector: %v", err)
		// Continue without Sigma detection
	} else {
		// Start Sigma detection polling (every 10 seconds)
		if err := sigmaDetector.StartPolling(10 * time.Second); err != nil {
			log.Printf("Warning: Failed to start Sigma detection: %v", err)
		}
	}

	// Start web server in background
	go func() {
		if err := startWebServer(db, sigmaDetector, binaryCache); err != nil {
			fmt.Printf("Web server error: %v\n", err)
		}
	}()
	fmt.Println("Web interface available at http://localhost:8080")

	// Only start BPF monitoring if we have a reader (not on Mac)
	if reader != nil && !*webOnly {
		// Create buffered channel for events
		eventChan := make(chan Event, 1000) // Buffer size to handle bursts

		// Start event processor and BPF reader
		go startEventProcessor(eventChan, collector, db, binaryCache)
		go startBPFReader(reader, eventChan)

		fmt.Println("Process monitoring started... Press Ctrl+C to stop")
	}

	// Set up signal handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	<-sig
	fmt.Println("Shutting down...")

	// Stop Sigma detector if it was running
	if sigmaDetector != nil {
		sigmaDetector.StopPolling()
	}
}

/*
struct event {
    // 8-byte aligned fields
    u64 timestamp;   // 8 bytes

    // 4-byte aligned fields
    u32 pid;         // 4 bytes
    u32 ppid;        // 4 bytes
    uid_t uid;       // 4 bytes
    gid_t gid;       // 4 bytes
    int event_type;  // 4 bytes
    int exit_code;   // 4 bytes
    u32 flags;       // 4 bytes

    // Variable-length fields
   x char comm[16];           // Process name
   x char parent_comm[16];    // Parent process name
    char filename[64];       // Executable path
    char cwd[64];            // Current working directory

    // For command line tracking
    u32 cmdline_map_id;      // ID to lookup command line in the map

} __attribute__((packed));
*/

func processExecEvent(evt Event, count int, collector *MetadataCollector, db *DB, binaryCache *BinaryCache) {
	// Each collection gets its own completion channel
	done := collector.CollectProcessInfo(evt.PID, evt.PPID)
	procinfo := <-done // We're guaranteed to get the right process's info

	if procinfo == nil {
		procinfo = &ProcessInfo{
			PID:  evt.PID,
			PPID: evt.PPID,
		}
	}

	// Use usermode process name from /proc if we have it, otherwise kernel-mode
	var comm string

	fmt.Printf("Evaluating %v\n", evt.PID)
	if len(bytes.TrimRight(evt.Comm[:], "\x00")) > 0 {
		kmcomm := string(bytes.TrimRight(evt.Comm[:], "\x00"))
		fmt.Printf("KM Comm [%v]\n", kmcomm)
	}
	fmt.Printf("UM Comm [%v]\n", procinfo.Comm)

	if len(procinfo.Comm) > 0 {
		comm = procinfo.Comm
	} else {
		if len(bytes.TrimRight(evt.Comm[:], "\x00")) > 0 {
			comm = string(bytes.TrimRight(evt.Comm[:], "\x00"))
		}
	}

	// Use usermode exe path from /proc if we have it, otherwise kernel-mode
	var exepath string
	if (evt.Flags&1 == 1) && (len(procinfo.ExePath) > 0) {
		// kernel verified this process has a valid exe
		exepath = procinfo.ExePath
	} else {
		fmt.Printf("processExecEvent flags %v procinfo.ExePath [%v]\n", evt.Flags, procinfo.ExePath)
		if len(bytes.TrimRight(evt.Filename[:], "\x00")) > 0 {
			exepath = string(bytes.TrimRight(evt.Filename[:], "\x00"))
		}
	}

	// Use usermode ParentComm if we have it, otherwise kernel-mode
	var parentComm string
	if len(procinfo.ParentComm) > 0 {
		parentComm = procinfo.ParentComm
	} else {
		if len(bytes.TrimRight(evt.ParentComm[:], "\x00")) > 0 {
			parentComm = string(bytes.TrimRight(evt.ParentComm[:], "\x00"))
		}
	}
	var workingDir string
	if len(procinfo.WorkingDir) > 0 {
		workingDir = procinfo.WorkingDir
	} else {
		if len(bytes.TrimRight(evt.CWD[:], "\x00")) > 0 {
			workingDir = string(bytes.TrimRight(evt.CWD[:], "\x00"))
		}
	}

	// try to get username from kernel-mode passed in uid
	var username string
	if evt.UID > 0 {
		if u, err := user.LookupId(fmt.Sprintf("%d", evt.UID)); err == nil {
			username = u.Username
		}
	}

	// Get command line from BPF map
	var cmdLine string
	if len(procinfo.CmdLine) > 0 {
		fmt.Printf("Using UM CmdLine: [%v]\n", procinfo.CmdLine)
		cmdLine = procinfo.CmdLine
	} else if cmdlinesMapFD != 0 {
		fullCmdLine, err := LookupCmdline(evt.PID)
		if err == nil && fullCmdLine != "" {
			fmt.Printf("Using KM CmdLine: [%v]\n", procinfo.CmdLine)
			cmdLine = fullCmdLine
		}
	}

	envJSON, _ := json.Marshal(procinfo.Environment)
	dbRecord := &ProcessRecord{
		Timestamp:   time.Unix(0, int64(evt.Timestamp)),
		PID:         evt.PID,
		PPID:        evt.PPID,
		Comm:        comm,
		CmdLine:     cmdLine,
		ExePath:     exepath,
		WorkingDir:  workingDir,
		Username:    username,
		ParentComm:  parentComm,
		Environment: string(envJSON),
		ContainerID: procinfo.ContainerID,
		UID:         fmt.Sprintf("%d", evt.UID),
		GID:         fmt.Sprintf("%d", evt.GID),
	}

	// Check if we have a valid executable path
	if dbRecord.ExePath != "" && !strings.HasPrefix(dbRecord.ExePath, "/proc/") &&
		!strings.HasPrefix(dbRecord.ExePath, "/dev/") && !strings.HasPrefix(dbRecord.ExePath, "/sys/") {

		// Calculate MD5 hash
		md5Hash, err := calculateMD5(dbRecord.ExePath)
		if err != nil {
			fmt.Printf("\nError calculating MD5 for %s: %v\n", dbRecord.ExePath, err)
		} else {
			// Add hash to the record
			dbRecord.BinaryMD5 = md5Hash

			// Check if binary is already in cache
			if !binaryCache.HasBinary(md5Hash) {
				// Check if binary exists on disk
				binPath := binaryCache.GetBinaryPath(md5Hash)
				if _, err := os.Stat(binPath); os.IsNotExist(err) {
					// Store the binary
					if err := binaryCache.StoreBinary(dbRecord.ExePath, md5Hash); err != nil {
						fmt.Printf("\nError storing binary %s: %v\n", dbRecord.ExePath, err)
					} else {
						fmt.Printf("\nStored binary: %s (MD5: %s)\n", dbRecord.ExePath, md5Hash)
					}
				}

				// Add to cache
				binaryCache.AddBinary(md5Hash)
			}
		}
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

func startEventProcessor(eventChan chan Event, collector *MetadataCollector, db *DB, binaryCache *BinaryCache) {
	fmt.Println("Starting event processor...")
	processCount := 0
	for event := range eventChan {
		switch event.EventType {
		case EventExec:
			processCount++
			go processExecEvent(event, processCount, collector, db, binaryCache)
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

		if event.EventType == EventExec {
			// Try to read command line from map
			if cmdlinesMapFD != 0 {
				key := event.PID

				// Lookup the command line from the map
				cmdLine, err := LookupCmdline(key)
				if err != nil {
					fmt.Printf("Failed to read command line for PID %d: %v\n", key, err)
				} else {
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
