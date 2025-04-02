package network

import (
    "fmt"
    "net"
    "sync"
)

// CreateConnectionInfo converts network event data to connection info
func CreateConnectionInfo(srcIP, dstIP net.IP, srcPort, dstPort uint16, pid uint32, comm string, proto uint8, containerID string) *ConnectionInfo {
    // Create connection info
    connInfo := &ConnectionInfo{
        PID:             pid,
        ProcessName:     comm,
        SourceIP:        srcIP,
        DestinationIP:   dstIP,
        SourcePort:      srcPort,
        DestinationPort: dstPort,
        ContainerID:     containerID,
    }
    
    // Determine protocol
    switch proto {
    case 6:
        connInfo.Protocol = "TCP"
    case 17:
        connInfo.Protocol = "UDP"
    default:
        connInfo.Protocol = fmt.Sprintf("Unknown(%d)", proto)
    }
    
    return connInfo
}

// FormatNetworkEvent formats a network event for display
func FormatNetworkEvent(connInfo *ConnectionInfo, eventType uint32) string {
    var eventTypeStr string
    
    switch eventType {
    case 3: // EVENT_NET_CONNECT
        eventTypeStr = "CONNECT"
    case 4: // EVENT_NET_ACCEPT
        eventTypeStr = "ACCEPT"
    case 5: // EVENT_NET_BIND
        eventTypeStr = "BIND"
    default:
        eventTypeStr = "UNKNOWN"
    }
    
    // Format basic connection information
    basic := fmt.Sprintf("%s: pid=%d comm=%s", 
        eventTypeStr, connInfo.PID, connInfo.ProcessName)
    
    // Format full connection details
    if eventType == 5 { // EVENT_NET_BIND
        // Bind events typically only have local address
        return fmt.Sprintf("%s local=%s:%d proto=%s", 
            basic, connInfo.SourceIP, connInfo.SourcePort, connInfo.Protocol)
    } else {
        // Connect/Accept events have both source and destination
        return fmt.Sprintf("%s src=%s:%d dst=%s:%d proto=%s", 
            basic, connInfo.SourceIP, connInfo.SourcePort, 
            connInfo.DestinationIP, connInfo.DestinationPort, connInfo.Protocol)
    }
}

// ConnectionMap provides a thread-safe way to track network connections
type ConnectionMap struct {
    connections []*ConnectionInfo
    mu          sync.RWMutex
}

// NewConnectionMap creates a new connection map
func NewConnectionMap() *ConnectionMap {
    return &ConnectionMap{
        connections: make([]*ConnectionInfo, 0),
    }
}

// AddConnection adds a new connection to the map
func (cm *ConnectionMap) AddConnection(info *ConnectionInfo) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    cm.connections = append(cm.connections, info)
}

// GetConnections returns all tracked connections
func (cm *ConnectionMap) GetConnections() []*ConnectionInfo {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    return append([]*ConnectionInfo{}, cm.connections...)
}

// GetConnectionsByPID returns all connections for a specific PID
func (cm *ConnectionMap) GetConnectionsByPID(pid uint32) []*ConnectionInfo {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    
    var pidConns []*ConnectionInfo
    for _, conn := range cm.connections {
        if conn.PID == pid {
            pidConns = append(pidConns, conn)
        }
    }
    return pidConns
}
