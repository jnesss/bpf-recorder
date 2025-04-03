package web

import (
	"time"
)

// ProcessRow represents a process for the web API
type ProcessRow struct {
	ID            int64      `json:"id"`
	Timestamp     time.Time  `json:"timestamp"`
	PID           uint32     `json:"pid"`
	PPID          uint32     `json:"ppid"`
	Comm          string     `json:"comm"`
	CmdLine       string     `json:"cmdline"`
	ExePath       string     `json:"exePath"`
	WorkingDir    string     `json:"workingDir"`
	Username      string     `json:"username"`
	ParentComm    string     `json:"parentComm"`
	ContainerID   string     `json:"containerId"`
	BinaryMD5     string     `json:"binaryMd5"`
	ExitTime      *time.Time `json:"exitTime,omitempty"`
	CPUUsage      *float64   `json:"cpuUsage,omitempty"`
	MemoryUsage   *uint64    `json:"memoryUsage,omitempty"`
	MemoryPercent *float64   `json:"memoryPercent,omitempty"`
	ThreadCount   *int       `json:"threadCount,omitempty"`
}

type NetworkRow struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	PID         uint32    `json:"pid"`
	ProcessName string    `json:"processName"`
	SrcAddr     string    `json:"srcAddr"`
	SrcPort     uint16    `json:"srcPort"`
	DstAddr     string    `json:"dstAddr"`
	DstPort     uint16    `json:"dstPort"`
	Protocol    string    `json:"protocol"`
	Operation   string    `json:"operation"`
	ContainerID string    `json:"containerId"`
}

// WebServer defines the interface for the web server
type WebServer interface {
	Start() error
	Stop() error
}
