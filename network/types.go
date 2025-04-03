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

// DNSInfo holds DNS query and response information
type DNSInfo struct {
	PID             uint32
	ProcessName     string
	SourceIP        net.IP
	DestinationIP   net.IP
	SourcePort      uint16
	DestinationPort uint16
	Timestamp       time.Time
	ContainerID     string

	// DNS specific fields
	TransactionID uint16
	QueryName     string
	QueryType     uint16
	IsResponse    bool
	Flags         uint16
	QuestionCount uint16
	AnswerCount   uint16
}

// TLSInfo holds TLS handshake information
type TLSInfo struct {
	PID             uint32
	ProcessName     string
	SourceIP        net.IP
	DestinationIP   net.IP
	SourcePort      uint16
	DestinationPort uint16
	Timestamp       time.Time
	ContainerID     string

	// TLS specific fields
	TLSVersion    uint16
	HandshakeType uint8
	SNI           string
	CipherSuites  []uint16
}

// ConnectionTracker defines the interface for connection tracking
type ConnectionTracker interface {
	AddConnection(info *ConnectionInfo)
	GetConnections() []*ConnectionInfo
	GetConnectionsByPID(pid uint32) []*ConnectionInfo
}

// DNSTracker defines the interface for DNS query/response tracking
type DNSTracker interface {
	AddDNSEvent(info *DNSInfo)
	GetDNSEvents() []*DNSInfo
	GetDNSEventsByPID(pid uint32) []*DNSInfo
	GetDNSEventsByQuery(query string) []*DNSInfo
}

// TLSTracker defines the interface for TLS handshake tracking
type TLSTracker interface {
	AddTLSEvent(info *TLSInfo)
	GetTLSEvents() []*TLSInfo
	GetTLSEventsByPID(pid uint32) []*TLSInfo
	GetTLSEventsBySNI(sni string) []*TLSInfo
}

// DNS query types (most common)
const (
	DNSTypeA     uint16 = 1
	DNSTypeNS    uint16 = 2
	DNSTypeCNAME uint16 = 5
	DNSTypeSOA   uint16 = 6
	DNSTypeWKS   uint16 = 11
	DNSTypePTR   uint16 = 12
	DNSTypeMX    uint16 = 15
	DNSTypeTXT   uint16 = 16
	DNSTypeAAAA  uint16 = 28
	DNSTypeSRV   uint16 = 33
	DNSTypeANY   uint16 = 255
)

// TLS versions
const (
	TLSv10 uint16 = 0x0301
	TLSv11 uint16 = 0x0302
	TLSv12 uint16 = 0x0303
	TLSv13 uint16 = 0x0304
)
