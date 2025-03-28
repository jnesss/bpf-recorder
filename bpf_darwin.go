//go:build darwin
// +build darwin

// This file provides a stub implementation for MacOS to enable development
// and testing without eBPF support. The actual monitoring functionality
// is only available on Linux systems.

package main

import "fmt"

// InitBPF provides a stub implementation for MacOS.
// This allows the project to be built and tested on MacOS development machines,
// while the actual eBPF monitoring functionality remains Linux-only.
func InitBPF() (PerfReader, func(), error) {
	return nil, nil, fmt.Errorf("eBPF monitoring is only supported on Linux systems. " +
		"This stub exists to enable development and testing on MacOS")
}
