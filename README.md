# BPF Recorder

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20|%20MacOS(UI%20Only)-lightgrey.svg)
![Language](https://img.shields.io/badge/language-Go-teal.svg)

A high-performance, low-overhead system for monitoring and analyzing process execution events in real-time using eBPF technology. BPF Recorder provides detailed telemetry for security monitoring, forensics, and system behavior analysis.

## Overview

BPF Recorder uses extended Berkeley Packet Filter (eBPF) technology to capture process lifecycle events directly from the Linux kernel with minimal performance impact. It offers:

- **Process Lifecycle Monitoring**: Captures process creation and termination events with complete metadata
- **Command Line Tracking**: Records full command lines with arguments 
- **Binary Preservation**: Automatically caches executable binaries for later forensic analysis
- **Real-time Detection**: Integrates Sigma rules for immediate threat detection
- **Container Awareness**: Identifies processes running inside containers
- **Cross-platform UI**: Web interface works on both Linux and MacOS for analysis and rule management

## Key Features

### 📊 Comprehensive Process Telemetry
- Full process genealogy with parent-child relationships
- Complete command line arguments and environment variables
- Working directory and executable path information
- User/group identity tracking
- Container context identification

### 🔍 Advanced Detection Capabilities
- Built-in [Sigma](https://github.com/SigmaHQ/sigma) rule support
- Real-time alerting based on process behavior
- Interactive rule management with enable/disable functionality
- User-friendly rule upload interface
- Detailed match information for investigations

### 🔒 Security-focused Architecture
- Privilege separation for database operations
- Binary preservation for forensic analysis
- MD5 hashing of executables for integrity verification
- Cross-platform design for development and deployment flexibility

### 📱 Intuitive Web Interface
- Real-time process monitoring dashboard
- Interactive process tree visualization
- Detailed process information display
- Rule management console
- Alert investigation tools

## Architecture

BPF Recorder is designed with a modular, secure architecture:

```
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│                   │   │                   │   │                   │
│   eBPF Monitoring │   │ Process Metadata  │   │  Binary Capture   │
│      (Kernel)     │◄──┼─ Collection       │◄──┼─   & Storage      │
│                   │   │  (User Space)     │   │                   │
└─────────┬─────────┘   └─────────┬─────────┘   └─────────┬─────────┘
          │                       │                       │
          │                       │                       │
          ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                               SQLite                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  │
                                  ▼
┌───────────────────────┐   ┌────────────────────┐   ┌───────────────────┐
│                       │   │                    │   │                   │
│   Process Monitoring  │   │   Sigma Detection  │   │ Interactive       │
│        Dashboard      │◄──┼─      Engine       │◄──┼─ Rule Management  │
│                       │   │                    │   │                   │
└───────────────────────┘   └────────────────────┘   └───────────────────┘
```

### Components:
- **eBPF Monitoring**: Kernel-level hooks for efficient event capture
- **Process Metadata Collection**: Enriches events with detailed process information
- **Binary Capture & Storage**: Preserves executables for analysis with customizable retention
- **Secure Database Layer**: SQLite with privilege separation
- **Detection Engine**: Real-time Sigma rule matching
- **Web Interface**: React-based dashboard for visualization and management

## Quick Start

### Requirements
- Linux 5.4+ for monitoring functionality (Web UI works on MacOS)
- Go 1.18+
- Clang/LLVM (for eBPF compilation)

### Installation

```bash
# Clone the repository
git clone https://github.com/jnesss/bpf-recorder.git
cd bpf-recorder

# Build the application
make

# Run with default settings (requires root/sudo for eBPF)
sudo ./bpf-recorder
```

### Usage Options

```bash
Usage: bpf-recorder [options]

Options:
  -data string        Directory for storing data (default "./data")
  -rules string       Directory for Sigma rules (default "./rules")
  -bins string        Directory for binary storage (default "./bins")
  -bin-cache-size int Size of in-memory binary cache (default 128)
  -web-only           Run in web UI only mode without BPF monitoring
```

## Web Interface

The web interface is available at `http://localhost:8080` and provides:

- Real-time process monitoring
- Interactive process tree visualization
- Rule management interface
- Alert dashboard

## Sigma Rules Integration

BPF Recorder supports [Sigma rules](https://github.com/SigmaHQ/sigma) for threat detection. Rules can be:

- Uploaded through the web interface
- Enabled/disabled through the UI
- Automatically monitored for file changes
- Customized for your environment

The system will automatically detect new rules and notify you of matches in real-time.

## Development

### Cross-platform Development
- The project is designed to allow development on MacOS (UI only) while production deployment on Linux
- Platform-specific code is isolated using Go build tags
- Testing can be performed on non-Linux systems

### Building for Different Platforms

**Linux (Full Functionality)**
```bash
make
```

**MacOS (UI Development Only)**
```bash
make build
```

## Security Considerations

BPF Recorder is designed with security in mind:
- Privilege separation for database operations
- Read-only storage of captured binaries
- Process metadata enrichment happens with dropped privileges
- Web interface runs with minimal permissions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.