//go:build darwin
// +build darwin

// This file provides a stub implementation for MacOS to enable development
// and testing without eBPF support. The actual monitoring functionality
// is only available on Linux systems.

package main

import "fmt"

var cmdlinesMapFD int // Will be 0 on macOS since BPF isn't supported

// InitBPF provides a stub implementation for MacOS.
// Returns nil reader but no error so the program can continue with web UI
func InitBPF() (PerfReader, func(), error) {
	fmt.Println("BPF monitoring not available on MacOS. Starting in web-only mode...")
	return nil, nil, nil
}

// No need for go:generate since we don't compile BPF code on macOS
