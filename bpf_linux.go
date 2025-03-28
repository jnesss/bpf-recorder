//go:build linux
// +build linux

// This file contains the Linux-specific eBPF implementation for process monitoring.
// It provides the concrete implementation of the platform-agnostic interfaces
// defined in reader.go.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang execve bpf/execve.c -- -I./bpf

import (
	"os"

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

var objs execveObjects

// InitBPF initializes the eBPF program and attaches it to system hooks.
// It returns:
// - A PerfReader for reading monitoring events
// - A cleanup function to detach hooks and free resources
// - Any error that occurred during initialization
func InitBPF() (PerfReader, func(), error) {
	// Remove rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, err
	}

	// Load pre-compiled BPF program
	if err := loadExecveObjects(&objs, nil); err != nil {
		return nil, nil, err
	}

	// Create perf reader
	reader, err := perf.NewReader(objs.Events, os.Getpagesize()*8)
	if err != nil {
		objs.Close()
		return nil, nil, err
	}

	// Attach execve tracepoint
	execveTP, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		reader.Close()
		objs.Close()
		return nil, nil, err
	}

	// Attach exit tracepoint
	exitTP, err := link.Tracepoint("sched", "sched_process_exit", objs.TracepointSchedSchedProcessExit, nil)
	if err != nil {
		execveTP.Close()
		reader.Close()
		objs.Close()
		return nil, nil, err
	}

	cleanup := func() {
		execveTP.Close()
		exitTP.Close()
		reader.Close()
		objs.Close()
	}

	return &perfReaderWrapper{reader}, cleanup, nil
}
