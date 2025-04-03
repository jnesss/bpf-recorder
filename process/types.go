package process

import (
	"sync"
	"time"
)

// ProcessInfo holds extended process information
type ProcessInfo struct {
	Mu sync.RWMutex // Protects all fields

	// Basic Info
	PID         uint32
	PPID        uint32
	Comm        string
	CmdLine     string
	ExePath     string
	UID         uint32
	GID         uint32
	Username    string
	Environment []string
	ContainerID string // if process is containerized
	ParentComm  string
	BinaryMD5   string

	// Timing Information
	StartTime time.Time
	ExitTime  time.Time
	ExitCode  uint32

	// Directory Tracking
	WorkingDir        string
	WorkingDirHistory []string // History of working directories

	// Dynamic Statistics (updated by StatsCollector)
	Stats *ProcessStats
}

// ProcessStats holds the dynamic statistics for a process
type ProcessStats struct {
	Mu sync.RWMutex // Protects all fields

	Timestamp     time.Time
	CPUUsage      float64   // CPU usage percentage
	MemoryUsage   uint64    // Memory usage in bytes
	MemoryPercent float64   // Memory usage percentage
	ThreadCount   int       // Number of threads
	FileDescCount int       // Number of open file descriptors
	OpenFiles     []string  // List of open files
	LastUpdated   time.Time // When these stats were last updated
}

// ProcessTracker defines the interface for process tracking
type ProcessTracker interface {
	Add(pid uint32, info *ProcessInfo)
	Get(pid uint32) (*ProcessInfo, bool)
	Remove(pid uint32)
	List() []*ProcessInfo
}

// StatsStorage defines what we need from our storage backend for process stats
type StatsStorage interface {
	UpdateProcessStats(pid uint32, stats *ProcessStats) error
}
