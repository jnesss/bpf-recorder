package platform

import "context"

// Event type constants
const (
	EVENT_PROCESS_EXEC = 1
	EVENT_PROCESS_EXIT = 2
	EVENT_NET_CONNECT  = 3
	EVENT_NET_ACCEPT   = 4
	EVENT_NET_BIND     = 5
)

// EventHeader is common to all event types
type EventHeader struct {
	EventType uint32
	Pid       uint32
	Timestamp uint64
	Comm      [16]byte
}

// ProcessEvent represents a process event from eBPF
type ProcessEvent struct {
	EventType  uint32
	Pid        uint32
	Timestamp  uint64
	Comm       [16]byte
	PPID       uint32
	UID        uint32
	GID        uint32
	ExitCode   uint32
	ParentComm [16]byte
	ExePath    [64]byte
	Flags      uint32
}

// NetworkEvent represents a network event from eBPF
type NetworkEvent struct {
	EventType uint32
	Pid       uint32
	Timestamp uint64
	Comm      [16]byte
	SAddrA    uint32
	SAddrB    uint32
	SAddrC    uint32
	SAddrD    uint32
	DAddrA    uint32
	DAddrB    uint32
	DAddrC    uint32
	DAddrD    uint32
	SPort     uint16
	DPort     uint16
	Protocol  uint8
}

// BPFMonitor interface defines what we need from our BPF implementation
type BPFMonitor interface {
	Start(context.Context) error
	Stop() error
}
