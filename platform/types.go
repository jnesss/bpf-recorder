package platform

import (
	"context"

	"github.com/jnesss/bpf-recorder/process"
)

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

type DNSEvent struct {
	EventType     uint32
	Pid           uint32
	Timestamp     uint64
	Comm          [16]byte
	SAddrA        uint32
	SAddrB        uint32
	SAddrC        uint32
	SAddrD        uint32
	DAddrA        uint32
	DAddrB        uint32
	DAddrC        uint32
	DAddrD        uint32
	SPort         uint16
	DPort         uint16
	OpFlags       uint8
	Txid          uint16
	Flags         uint16
	QuestionCount uint16
	AnswerCount   uint16
	IsResponse    uint8
	QueryType     uint16
	QueryName     [128]byte
}

type TLSEvent struct {
	EventType     uint32
	Pid           uint32
	Timestamp     uint64
	Comm          [16]byte
	SAddrA        uint32
	SAddrB        uint32
	SAddrC        uint32
	SAddrD        uint32
	DAddrA        uint32
	DAddrB        uint32
	DAddrC        uint32
	DAddrD        uint32
	SPort         uint16
	DPort         uint16
	TlsVersion    uint16
	HandshakeType uint8
	CipherLen     uint8
	Ciphers       [8]uint16
	Sni           [128]byte
}

// BPFMonitor interface defines what we need from our BPF implementation
type BPFMonitor interface {
	Start(context.Context) error
	Stop() error
	GetProcessMap() *process.ProcessMap
}

// MonitorConfig holds configuration for creating a new monitor
type MonitorConfig struct {
	DB          interface{} // Using interface{} since we don't want to import database package here
	BinaryCache interface{} // Same for binary cache
	ProcessMap  *process.ProcessMap
	CgroupPath  string
}
