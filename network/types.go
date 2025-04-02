package network

import (
    "net"
    "time"
)

// ConnectionInfo holds extended connection information
type ConnectionInfo struct {
    PID             uint32
    ProcessName     string
    SourceIP        net.IP
    DestinationIP   net.IP
    SourcePort      uint16
    DestinationPort uint16
    Protocol        string
    Timestamp       time.Time
    ContainerID     string
}

// ConnectionTracker defines the interface for connection tracking
type ConnectionTracker interface {
    AddConnection(info *ConnectionInfo)
    GetConnections() []*ConnectionInfo
    GetConnectionsByPID(pid uint32) []*ConnectionInfo
}
