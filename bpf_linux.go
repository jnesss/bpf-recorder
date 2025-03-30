//go:build linux
// +build linux

// This file contains the Linux-specific eBPF implementation for process monitoring.
// It provides the concrete implementation of the platform-agnostic interfaces
// defined in reader.go.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang execve bpf/execve.c -- -I./bpf

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
	objs          execveObjects
	cmdlinesMapFD int // For the command line map
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

	// Load pre-compiled BPF program
	if err := loadExecveObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load BPF objects: %v", err)
	}

	// Create perf reader
	reader, err := perf.NewReader(objs.Events, os.Getpagesize()*8)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("failed to create perf reader: %v", err)
	}

	// Get the cmdlines map FD
	cmdlinesMapFD = objs.Cmdlines.FD()

	var cleanupFuncs []func()
	cleanupFuncs = append(cleanupFuncs, func() {
		reader.Close()
		objs.Close()
	})

	// Attach execve tracepoint
	execveTP, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		for _, cleanup := range cleanupFuncs {
			cleanup()
		}
		return nil, nil, fmt.Errorf("failed to attach execve tracepoint: %v", err)
	}
	cleanupFuncs = append(cleanupFuncs, func() { execveTP.Close() })

	// Try to attach exit tracepoint, but continue if it fails
	exitTP, err := link.Tracepoint("sched", "sched_process_exit", objs.TracepointSchedSchedProcessExit, nil)
	if err != nil {
		fmt.Printf("Warning: Could not attach exit tracepoint: %v\n", err)
		fmt.Println("Continuing with process creation monitoring only...")
	} else {
		cleanupFuncs = append(cleanupFuncs, func() { exitTP.Close() })
	}

	cleanup := func() {
		// Execute cleanup functions in reverse order
		for i := len(cleanupFuncs) - 1; i >= 0; i-- {
			cleanupFuncs[i]()
		}
	}

	return &perfReaderWrapper{reader}, cleanup, nil
}

// LookupCmdline retrieves the command line for a process
func LookupCmdline(pid uint32) (string, error) {
	// Make sure we have a valid map
	if objs.Cmdlines == nil {
		return "", fmt.Errorf("cmdlines map not initialized")
	}

	// Create buffer for reading from map
	var value [1024]byte // Increased to match BPF code

	// Lookup the value
	err := objs.Cmdlines.Lookup(&pid, &value)
	if err != nil {
		return "", fmt.Errorf("map lookup error: %v", err)
	}

	// Convert to string and trim nulls
	cmdLine := strings.TrimRight(string(value[:]), "\x00")
	return cmdLine, nil
}
