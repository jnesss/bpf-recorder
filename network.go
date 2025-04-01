package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// NetworkRecord represents a network connection for database storage
type NetworkRecord struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	UID         string    `json:"uid"`
	GID         string    `json:"gid"`
	ProcessName string    `json:"process_name"`
	ExePath     string    `json:"exe_path"`
	ParentName  string    `json:"parent_name"`
	SrcAddr     string    `json:"src_addr"`
	SrcPort     uint16    `json:"src_port"`
	DstAddr     string    `json:"dst_addr"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	IPVersion   uint8     `json:"ip_version"`
	Operation   string    `json:"operation"`
	ReturnCode  int32     `json:"return_code"`
	Success     bool      `json:"success"`
	Username    string    `json:"username"`
	ContainerID string    `json:"container_id"`
}

// processNetworkEvent processes a network event from eBPF and creates a record
func processNetworkEvent(netEvent NetworkEvent, collector *MetadataCollector, db *DB) error {
	// Convert network event to a record
	record := &NetworkRecord{
		Timestamp:   time.Unix(0, int64(netEvent.Timestamp)),
		PID:         netEvent.PID,
		PPID:        netEvent.PPID,
		UID:         fmt.Sprintf("%d", netEvent.UID),
		GID:         fmt.Sprintf("%d", netEvent.GID),
		ProcessName: bytesToString(netEvent.Comm[:]),
		ExePath:     bytesToString(netEvent.ExePath[:]),
		ParentName:  bytesToString(netEvent.ParentComm[:]),
		ReturnCode:  netEvent.ReturnCode,
		IPVersion:   netEvent.IPVersion,
	}

	// Set success flag based on return code
	record.Success = netEvent.ReturnCode >= 0

	// Convert source and destination addresses
	if netEvent.IPVersion == 4 {
		// IPv4
		record.SrcAddr = ipv4ToString(netEvent.SrcAddrV4)
		record.DstAddr = ipv4ToString(netEvent.DstAddrV4)
	} else if netEvent.IPVersion == 6 {
		// IPv6
		record.SrcAddr = ipv6ToString(netEvent.SrcAddrV6)
		record.DstAddr = ipv6ToString(netEvent.DstAddrV6)
	}

	// Set ports
	record.SrcPort = netEvent.SrcPort
	record.DstPort = netEvent.DstPort

	// Set protocol
	switch netEvent.Protocol {
	case NetProtocolTCP:
		record.Protocol = "TCP"
	case NetProtocolUDP:
		record.Protocol = "UDP"
	default:
		record.Protocol = fmt.Sprintf("UNKNOWN(%d)", netEvent.Protocol)
	}

	// Set operation type
	switch netEvent.Operation {
	case NetOperationConnect:
		record.Operation = "connect"
	case NetOperationAccept:
		record.Operation = "accept"
	case NetOperationBind:
		record.Operation = "bind"
	default:
		record.Operation = fmt.Sprintf("unknown(%d)", netEvent.Operation)
	}

	// Enrich with metadata from collector
	enrichNetworkRecord(record, collector)

	// Insert record into the database
	if err := db.InsertNetworkConnection(record); err != nil {
		return fmt.Errorf("error inserting network record: %v", err)
	}

	return nil
}

// enrichNetworkRecord adds additional metadata to a network record
func enrichNetworkRecord(record *NetworkRecord, collector *MetadataCollector) {
	// Try to get existing process info
	procInfo := collector.GetProcessInfo(record.PID)
	if procInfo != nil {
		// Use more detailed info if available
		if procInfo.Username != "" {
			record.Username = procInfo.Username
		}
		if procInfo.ContainerID != "" {
			record.ContainerID = procInfo.ContainerID
		}
		// Use process CmdLine if available (will be included in future UI)
	}
}

// ipv4ToString converts a 32-bit IPv4 address to a string
func ipv4ToString(addr uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip.String()
}

// ipv6ToString converts a 4x32-bit IPv6 address to a string
func ipv6ToString(addr [4]uint32) string {
	ip := make(net.IP, 16)

	// Convert array of 4 uint32 to 16 bytes
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(ip[i*4:], addr[i])
	}

	return ip.String()
}

// bytesToString converts a byte array to a string, truncating at the first null byte
func bytesToString(bytes []byte) string {
	for i, b := range bytes {
		if b == 0 {
			return string(bytes[:i])
		}
	}
	return string(bytes)
}
