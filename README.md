# BPF Recorder

A lightweight process monitoring system using eBPF to track process creation and termination events on Linux systems.

## Overview

BPF Recorder uses eBPF to monitor process lifecycle events (creation and termination) on Linux systems. It provides detailed information about each process, including:
- Process ID and Parent Process ID
- Command name and arguments
- Process tree showing the chain of parent processes
- Exit codes for terminated processes

## Project Structure

The project is designed to support development on both Linux and MacOS systems:

```
.
├── main.go              # Main application logic
├── reader.go            # Platform-agnostic interfaces
├── process.go           # Process monitoring logic
├── bpf_linux.go        # Linux-specific eBPF implementation
├── bpf_darwin.go       # MacOS build support (stub)
├── execve.c            # eBPF program (C code)
└── headers/            # eBPF header files
```

### Development Architecture

- The core monitoring logic is platform-independent, using interfaces defined in `reader.go`
- Platform-specific code is isolated using Go build tags
- MacOS support is included to enable development and testing on non-Linux systems
- The actual eBPF monitoring functionality only runs on Linux

## Building

### On Linux (Full Functionality)
```bash
go build
```

### On MacOS (Development Only)
```bash
CGO_ENABLED=1 go build -tags darwin
```

Note: The MacOS build will compile but will exit with an "eBPF not supported" message when run.

## Usage

```bash
# Run with default settings
./bpf-recorder

# Use Ctrl+C to stop monitoring
```

## Requirements

- Linux 5.4+ for running the monitor
- Go 1.18+
- CGO enabled
- Clang/LLVM (for eBPF compilation)

## Development Notes

- The project uses build tags to separate Linux and MacOS code
- Platform-agnostic interfaces allow for future extensions
- Error handling and logging are designed for production use
- The architecture supports easy testing and mocking