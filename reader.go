// Package main provides a cross-platform process monitoring system.
//
// The architecture uses platform-independent interfaces to allow for:
// 1. Development and testing on non-Linux systems (e.g., MacOS)
// 2. Future extension to other monitoring backends beyond eBPF
// 3. Easier testing through the ability to mock event sources
package main

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
