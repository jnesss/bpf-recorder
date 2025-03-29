// Package main provides a cross-platform process monitoring system.
//
// The architecture uses platform-independent interfaces to allow for:
// 1. Development and testing on non-Linux systems (e.g., MacOS)
// 2. Future extension to other monitoring backends beyond eBPF
// 3. Easier testing through the ability to mock event sources
package main

// Event types
const (
	EventExec = 1
	EventExit = 2
)

// Event represents a process event from the BPF layer
type Event struct {
	// 8-byte aligned fields
	Timestamp uint64

	// 4-byte aligned fields
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	EventType int32
	ExitCode  int32

	// Variable-length fields
	Comm       [16]byte
	ParentComm [16]byte
	Filename   [64]byte
	CWD        [64]byte

	// Command line in the structure
	Cmdline     [144]byte
	CmdlineLen  uint32
	IsTruncated uint8
	Pad         [3]byte
}

// PerfReader defines a platform-agnostic interface for reading monitoring events.
// On Linux, this is implemented using eBPF's perf buffer.
// This abstraction allows the core logic to remain platform-independent
// and simplifies development/testing on non-Linux systems.
type PerfReader interface {
	// Read returns the next event record
	Read() (Record, error)
	// Close cleans up any resources
	Close() error
}

// Record represents a monitoring event record.
// This structure mirrors the essential fields from eBPF's perf.Record
// but remains platform-independent to allow compilation on non-Linux systems.
type Record struct {
	// RawSample contains the raw event data
	RawSample []byte
	// LostSamples indicates how many samples were dropped by the kernel
	LostSamples uint64
}
