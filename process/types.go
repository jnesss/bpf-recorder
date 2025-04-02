package process

import (
    "time"
)

// ProcessInfo holds extended process information
type ProcessInfo struct {
    PID           uint32
    PPID          uint32
    Comm          string
    CmdLine       string
    ExePath       string
    UID           uint32
    GID           uint32
    Username      string
    StartTime     time.Time
    ExitTime      time.Time
    ExitCode      uint32
    WorkingDir    string
    ContainerID   string // if process is containerized
    ParentComm    string 
    BinaryMD5     string
}

// ProcessTracker defines the interface for process tracking
type ProcessTracker interface {
    Add(pid uint32, info *ProcessInfo)
    Get(pid uint32) (*ProcessInfo, bool)
    Remove(pid uint32)
    List() []*ProcessInfo
}
