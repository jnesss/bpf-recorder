//go:build linux
// +build linux

// This file contains the Linux-specific eBPF implementation for process monitoring.
// It provides the concrete implementation of the platform-agnostic interfaces
// defined in reader.go.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang execve bpf/execve.c -- -I./bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang network bpf/network.c -- -I./bpf

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// perfReaderWrapper adapts the eBPF perf.Reader to our platform-agnostic PerfReader interface.
// This wrapper allows the main application logic to remain independent of the eBPF implementation details.
type perfReaderWrapper struct {
	*perf.Reader
}

// Read implements the PerfReader interface by converting eBPF-specific types
// to our platform-agnostic Record type.
func (w *perfReaderWrapper) Read() (Record, error) {
	record, err := w.Reader.Read()
	if err != nil {
		return Record{}, err
	}
	return Record{
		RawSample:   record.RawSample,
		LostSamples: record.LostSamples,
	}, nil
}

var (
	execveObjs    execveObjects
	networkObjs   networkObjects
	cmdlinesMapFD int // For the command line map
	readers       []*perf.Reader
)

// InitBPF initializes the eBPF program and attaches it to system hooks.
// It returns:
// - A PerfReader for reading monitoring events
// - A cleanup function to detach hooks and free resources
// - Any error that occurred during initialization
func InitBPF() (PerfReader, func(), error) {
	// Remove rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("failed to remove rlimit: %v", err)
	}

	// Load pre-compiled BPF programs
	if err := loadExecveObjects(&execveObjs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load process BPF objects: %v", err)
	}

	// Create perf reader for process events
	procReader, err := perf.NewReader(execveObjs.Events, os.Getpagesize()*8)
	if err != nil {
		execveObjs.Close()
		return nil, nil, fmt.Errorf("failed to create process perf reader: %v", err)
	}
	readers = append(readers, procReader)

	// Get the cmdlines map FD
	cmdlinesMapFD = execveObjs.Cmdlines.FD()

	// Load network BPF objects
	if err := loadNetworkObjects(&networkObjs, nil); err != nil {
		fmt.Printf("Warning: Failed to load network BPF objects: %v\n", err)
		fmt.Println("Continuing with process monitoring only...")
	} else {
		// Create perf reader for network events
		netReader, err := perf.NewReader(networkObjs.NetworkEvents, os.Getpagesize()*8)
		if err != nil {
			fmt.Printf("Warning: Failed to create network perf reader: %v\n", err)
			fmt.Println("Continuing with process monitoring only...")
			networkObjs.Close()
		} else {
			readers = append(readers, netReader)
		}
	}

	var cleanupFuncs []func()
	cleanupFuncs = append(cleanupFuncs, func() {
		for _, reader := range readers {
			reader.Close()
		}
		execveObjs.Close()
		networkObjs.Close()
	})

	// Attach execve tracepoint
	execveTP, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		for _, cleanup := range cleanupFuncs {
			cleanup()
		}
		return nil, nil, fmt.Errorf("failed to attach execve tracepoint: %v", err)
	}
	cleanupFuncs = append(cleanupFuncs, func() { execveTP.Close() })

	// Try to attach exit tracepoint, but continue if it fails
	exitTP, err := link.Tracepoint("sched", "sched_process_exit", execveObjs.TracepointSchedSchedProcessExit, nil)
	if err != nil {
		fmt.Printf("Warning: Could not attach exit tracepoint: %v\n", err)
		fmt.Println("Continuing with process creation monitoring only...")
	} else {
		cleanupFuncs = append(cleanupFuncs, func() { exitTP.Close() })
	}

	// Attach network kprobes if loaded successfully
	if networkObjs.KprobesSysConnect != nil {
		// Attach connect kprobe
		connectKprobe, err := link.Kprobe("sys_connect", networkObjs.KprobesSysConnect, nil)
		if err != nil {
			fmt.Printf("Warning: Could not attach connect kprobe: %v\n", err)
		} else {
			cleanupFuncs = append(cleanupFuncs, func() { connectKprobe.Close() })
		}

		// Attach connect kretprobe
		connectKretprobe, err := link.Kretprobe("sys_connect", networkObjs.KretprobesSysConnect, nil)
		if err != nil {
			fmt.Printf("Warning: Could not attach connect kretprobe: %v\n", err)
		} else {
			cleanupFuncs = append(cleanupFuncs, func() { connectKretprobe.Close() })
		}

		// Attach accept kprobe
		acceptKprobe, err := link.Kprobe("sys_accept", networkObjs.KprobesSysAccept, nil)
		if err != nil {
			fmt.Printf("Warning: Could not attach accept kprobe: %v\n", err)
		} else {
			cleanupFuncs = append(cleanupFuncs, func() { acceptKprobe.Close() })
		}

		// Attach accept kretprobe
		acceptKretprobe, err := link.Kretprobe("sys_accept", networkObjs.KretprobesSysAccept, nil)
		if err != nil {
			fmt.Printf("Warning: Could not attach accept kretprobe: %v\n", err)
		} else {
			cleanupFuncs = append(cleanupFuncs, func() { acceptKretprobe.Close() })
		}

		// Attach bind kprobe
		bindKprobe, err := link.Kprobe("sys_bind", networkObjs.KprobesSysBind, nil)
		if err != nil {
			fmt.Printf("Warning: Could not attach bind kprobe: %v\n", err)
		} else {
			cleanupFuncs = append(cleanupFuncs, func() { bindKprobe.Close() })
		}

		// Attach bind kretprobe
		bindKretprobe, err := link.Kretprobe("sys_bind", networkObjs.KretprobesSysBind, nil)
		if err != nil {
			fmt.Printf("Warning: Could not attach bind kretprobe: %v\n", err)
		} else {
			cleanupFuncs = append(cleanupFuncs, func() { bindKretprobe.Close() })
		}
	}

	cleanup := func() {
		// Execute cleanup functions in reverse order
		for i := len(cleanupFuncs) - 1; i >= 0; i-- {
			cleanupFuncs[i]()
		}
	}

	// Create a multi-reader wrapper to handle multiple perf buffers
	multiReader := newMultiPerfReader(readers)

	return &perfReaderWrapper{multiReader}, cleanup, nil
}

// MultiPerfReader handles reading from multiple perf buffers
type MultiPerfReader struct {
	readers []*perf.Reader
}

func newMultiPerfReader(readers []*perf.Reader) *perf.Reader {
	// For simplicity, we'll just return the first reader
	// In a more sophisticated implementation, you might:
	// 1. Create a custom reader that multiplexes between multiple perf readers
	// 2. Use channels to coordinate reading from multiple sources
	// 3. Use polling to efficiently monitor multiple perf buffers
	if len(readers) > 0 {
		return readers[0]
	}
	return nil
}

// LookupCmdline retrieves the command line for a process
func LookupCmdline(pid uint32) (string, error) {
	// Make sure we have a valid map
	if execveObjs.Cmdlines == nil {
		return "", fmt.Errorf("cmdlines map not initialized")
	}

	// Create buffer for reading from map
	var value [1024]byte

	// Lookup the value
	err := execveObjs.Cmdlines.Lookup(&pid, &value)
	if err != nil {
		return "", fmt.Errorf("map lookup error: %v", err)
	}

	// Replace nulls with spaces and handle non-printable characters
	var builder strings.Builder
	inNull := false
	for i, b := range value {
		if b == 0 {
			if !inNull {
				builder.WriteByte(' ')
				inNull = true
			}
		} else if b >= 32 && b <= 126 { // ASCII printable range
			builder.WriteByte(b)
			inNull = false
		} else if b == 9 || b == 10 || b == 13 { // Tab, LF, CR
			if !inNull {
				builder.WriteByte(' ')
				inNull = true
			}
		}

		// Break at the end
		if i >= 1023 {
			break
		}
	}

	// Clean up consecutive spaces
	cmdLine := builder.String()
	for strings.Contains(cmdLine, "  ") {
		cmdLine = strings.ReplaceAll(cmdLine, "  ", " ")
	}

	return strings.TrimSpace(cmdLine), nil
}
