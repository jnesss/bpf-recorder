package web

import (
    "time"
)

// ProcessRow represents a process for the web API
type ProcessRow struct {
    ID          int64     `json:"id"`
    Timestamp   time.Time `json:"timestamp"`
    PID         uint32    `json:"pid"`
    PPID        uint32    `json:"ppid"`
    Comm        string    `json:"comm"`
    CmdLine     string    `json:"cmdline"`
    ExePath     string    `json:"exePath"`
    WorkingDir  string    `json:"workingDir"`
    Username    string    `json:"username"`
    ParentComm  string    `json:"parentComm"`
    ContainerID string    `json:"containerId"`
    BinaryMD5   string    `json:"binaryMd5"`
}

// WebServer defines the interface for the web server
type WebServer interface {
    Start() error
    Stop() error
}
