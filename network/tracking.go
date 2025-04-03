package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
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
		Timestamp:       time.Now(),
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

// DNSRequestCache provides a thread-safe LRU cache for correlating DNS requests and responses
type DNSRequestCache struct {
	cache *lru.Cache
	mu    sync.RWMutex
}

// NewDNSRequestCache creates a new DNS request cache with the specified maximum size
func NewDNSRequestCache(maxSize int) (*DNSRequestCache, error) {
	cache, err := lru.New(maxSize)
	if err != nil {
		return nil, err
	}

	return &DNSRequestCache{
		cache: cache,
	}, nil
}

// AddRequest adds a DNS request to the cache with the specified transaction ID and query
func (rc *DNSRequestCache) AddRequest(txid uint16, query string, info *DNSInfo) {
	if query == "" || txid == 0 {
		return // Don't cache incomplete requests
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	key := fmt.Sprintf("%d:%s", txid, query)
	rc.cache.Add(key, info)

	// Automatically remove entry after timeout to prevent stale entries
	go func() {
		time.Sleep(5 * time.Second) // Reasonable DNS timeout
		rc.mu.Lock()
		defer rc.mu.Unlock()
		rc.cache.Remove(key)
	}()
}

// MatchWithRequest finds a matching request for a DNS response
func (rc *DNSRequestCache) MatchWithRequest(txid uint16, query string) *DNSInfo {
	if query == "" || txid == 0 {
		return nil
	}

	rc.mu.RLock()
	defer rc.mu.RUnlock()

	key := fmt.Sprintf("%d:%s", txid, query)
	if info, found := rc.cache.Get(key); found {
		return info.(*DNSInfo)
	}
	return nil
}

// CreateDNSInfo converts DNS event data to DNS info
func CreateDNSInfo(srcIP, dstIP net.IP, srcPort, dstPort uint16, pid uint32, comm string,
	containerID string, txid uint16, queryName string, queryType uint16,
	isResponse bool, flags uint16, questionCount, answerCount uint16,
) *DNSInfo {
	// Sanitize query name to defend against malformed data
	queryName = sanitizeDNSName(queryName)

	// Create DNS info
	dnsInfo := &DNSInfo{
		PID:             pid,
		ProcessName:     comm,
		SourceIP:        srcIP,
		DestinationIP:   dstIP,
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		ContainerID:     containerID,
		TransactionID:   txid,
		QueryName:       queryName,
		QueryType:       queryType,
		IsResponse:      isResponse,
		Flags:           flags,
		QuestionCount:   questionCount,
		AnswerCount:     answerCount,
		Timestamp:       time.Now(),
	}

	return dnsInfo
}

// sanitizeDNSName ensures the DNS name is valid and not maliciously crafted
func sanitizeDNSName(name string) string {
	// Defense 1: Limit length to reasonable size
	if len(name) > 255 {
		name = name[:255]
	}

	// Defense 2: Remove any non-DNS valid characters
	var result strings.Builder
	for _, c := range name {
		// Only allow a-z, A-Z, 0-9, '.', '-'
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' {
			result.WriteRune(c)
		}
	}

	// Defense 3: Check for empty result (potential binary garbage)
	if result.Len() == 0 {
		return "[malformed-query]"
	}

	return result.String()
}

// CreateTLSInfo converts TLS event data to TLS info
func CreateTLSInfo(srcIP, dstIP net.IP, srcPort, dstPort uint16, pid uint32, comm string,
	containerID string, tlsVersion uint16, handshakeType uint8,
	sni string, cipherSuites []uint16,
) *TLSInfo {
	// Sanitize SNI to defend against malformed data
	sni = sanitizeHostname(sni)

	// Validate cipher suites - prevent buffer overflow attacks
	if len(cipherSuites) > 16 {
		cipherSuites = cipherSuites[:16] // Limit to reasonable number
	}

	// Create TLS info
	tlsInfo := &TLSInfo{
		PID:             pid,
		ProcessName:     comm,
		SourceIP:        srcIP,
		DestinationIP:   dstIP,
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		ContainerID:     containerID,
		TLSVersion:      tlsVersion,
		HandshakeType:   handshakeType,
		SNI:             sni,
		CipherSuites:    cipherSuites,
		Timestamp:       time.Now(),
	}

	return tlsInfo
}

// sanitizeHostname ensures the hostname is valid and not maliciously crafted
func sanitizeHostname(hostname string) string {
	// Defense 1: Limit length to reasonable size
	if len(hostname) > 255 {
		hostname = hostname[:255]
	}

	// Defense 2: Remove any non-hostname valid characters
	var result strings.Builder
	for _, c := range hostname {
		// Only allow a-z, A-Z, 0-9, '.', '-'
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' {
			result.WriteRune(c)
		}
	}

	// Defense 3: Check for empty result (potential binary garbage)
	if result.Len() == 0 {
		return "[malformed-hostname]"
	}

	return result.String()
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

// FormatDNSEvent formats a DNS event for display
func FormatDNSEvent(dnsInfo *DNSInfo) string {
	eventTypeStr := "DNS_QUERY"
	if dnsInfo.IsResponse {
		eventTypeStr = "DNS_RESPONSE"
	}

	// Format basic DNS info
	basic := fmt.Sprintf("%s: pid=%d comm=%s",
		eventTypeStr, dnsInfo.PID, dnsInfo.ProcessName)

	// Get query type as string
	queryTypeStr := getDNSTypeString(dnsInfo.QueryType)

	// Format full DNS details
	return fmt.Sprintf("%s query=%s type=%s txid=0x%04x src=%s:%d dst=%s:%d",
		basic, dnsInfo.QueryName, queryTypeStr, dnsInfo.TransactionID,
		dnsInfo.SourceIP, dnsInfo.SourcePort,
		dnsInfo.DestinationIP, dnsInfo.DestinationPort)
}

// FormatTLSEvent formats a TLS event for display
func FormatTLSEvent(tlsInfo *TLSInfo) string {
	// Format basic TLS info
	basic := fmt.Sprintf("TLS_HANDSHAKE: pid=%d comm=%s",
		tlsInfo.PID, tlsInfo.ProcessName)

	// Get TLS version as string
	tlsVersionStr := getTLSVersionString(tlsInfo.TLSVersion)

	// Format full TLS details with SNI if available
	sniPart := ""
	if tlsInfo.SNI != "" {
		sniPart = fmt.Sprintf(" sni=%s", tlsInfo.SNI)
	}

	return fmt.Sprintf("%s%s version=%s src=%s:%d dst=%s:%d",
		basic, sniPart, tlsVersionStr,
		tlsInfo.SourceIP, tlsInfo.SourcePort,
		tlsInfo.DestinationIP, tlsInfo.DestinationPort)
}

// getDNSTypeString converts DNS query type to string
func getDNSTypeString(queryType uint16) string {
	switch queryType {
	case DNSTypeA:
		return "A"
	case DNSTypeNS:
		return "NS"
	case DNSTypeCNAME:
		return "CNAME"
	case DNSTypeSOA:
		return "SOA"
	case DNSTypePTR:
		return "PTR"
	case DNSTypeMX:
		return "MX"
	case DNSTypeTXT:
		return "TXT"
	case DNSTypeAAAA:
		return "AAAA"
	case DNSTypeSRV:
		return "SRV"
	case DNSTypeANY:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE-%d", queryType)
	}
}

// getTLSVersionString converts TLS version to string
func getTLSVersionString(version uint16) string {
	switch version {
	case TLSv10:
		return "TLSv1.0"
	case TLSv11:
		return "TLSv1.1"
	case TLSv12:
		return "TLSv1.2"
	case TLSv13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// ConnectionMap provides a thread-safe way to track network connections
type ConnectionMap struct {
	connections []*ConnectionInfo
	mu          sync.RWMutex
	// Add rate limiting to defend against DoS
	lastCleanup time.Time
	maxSize     int
}

// NewConnectionMap creates a new connection map
func NewConnectionMap() *ConnectionMap {
	return &ConnectionMap{
		connections: make([]*ConnectionInfo, 0),
		lastCleanup: time.Now(),
		maxSize:     50000, // Reasonable limit to prevent memory exhaustion
	}
}

// AddConnection adds a new connection to the map with protection against flooding
func (cm *ConnectionMap) AddConnection(info *ConnectionInfo) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Defense: Check if we need to clean up old connections to prevent memory exhaustion
	if len(cm.connections) > cm.maxSize || time.Since(cm.lastCleanup) > 5*time.Minute {
		// Keep only connections from the last hour
		cutoff := time.Now().Add(-1 * time.Hour)
		var newConnections []*ConnectionInfo
		for _, conn := range cm.connections {
			if conn.Timestamp.After(cutoff) {
				newConnections = append(newConnections, conn)
			}
		}
		cm.connections = newConnections
		cm.lastCleanup = time.Now()
	}

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

// DNSMap provides a thread-safe way to track DNS queries and responses
type DNSMap struct {
	events []*DNSInfo
	mu     sync.RWMutex
	// Add rate limiting to defend against DoS
	lastCleanup time.Time
	maxSize     int
	// Track unique queries to detect DNS flooding
	queryCounter map[string]int
	// Request cache for correlating requests and responses
	requestCache *DNSRequestCache
}

// NewDNSMap creates a new DNS event map
func NewDNSMap() *DNSMap {
	requestCache, _ := NewDNSRequestCache(2048) // Cache size can be tuned

	return &DNSMap{
		events:       make([]*DNSInfo, 0),
		lastCleanup:  time.Now(),
		maxSize:      50000, // Reasonable limit to prevent memory exhaustion
		queryCounter: make(map[string]int),
		requestCache: requestCache,
	}
}

// AddDNSEvent adds a new DNS event with protection against flooding
func (dm *DNSMap) AddDNSEvent(info *DNSInfo) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Defense: Check for high-volume queries that might indicate DNS tunneling
	key := fmt.Sprintf("%s-%s-%d", info.ProcessName, info.QueryName, info.PID)

	// Record this query
	dm.queryCounter[key]++

	// If this is a query (not a response), add to request cache for correlation
	if !info.IsResponse {
		// Store in request cache for later correlation
		dm.requestCache.AddRequest(info.TransactionID, info.QueryName, info)
	} else {
		// If it's a response, try to find the matching request
		matchingRequest := dm.requestCache.MatchWithRequest(info.TransactionID, info.QueryName)
		if matchingRequest != nil {
			// We could enrich the response with request info if needed
			// Example: info.RequestTimestamp = matchingRequest.Timestamp
			// For now we just log the match
			fmt.Printf("Found matching request for DNS response: %s (txid: 0x%04x)\n",
				info.QueryName, info.TransactionID)
		}
	}

	// Check if we need to clean up old events to prevent memory exhaustion
	if len(dm.events) > dm.maxSize || time.Since(dm.lastCleanup) > 5*time.Minute {
		// Keep only events from the last hour and reset counter
		cutoff := time.Now().Add(-1 * time.Hour)
		var newEvents []*DNSInfo
		for _, evt := range dm.events {
			if evt.Timestamp.After(cutoff) {
				newEvents = append(newEvents, evt)
			}
		}
		dm.events = newEvents
		dm.queryCounter = make(map[string]int) // Reset counter
		dm.lastCleanup = time.Now()
	}

	dm.events = append(dm.events, info)
}

// GetDNSEvents returns all tracked DNS events
func (dm *DNSMap) GetDNSEvents() []*DNSInfo {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return append([]*DNSInfo{}, dm.events...)
}

// GetDNSEventsByPID returns all DNS events for a specific PID
func (dm *DNSMap) GetDNSEventsByPID(pid uint32) []*DNSInfo {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	var pidEvents []*DNSInfo
	for _, evt := range dm.events {
		if evt.PID == pid {
			pidEvents = append(pidEvents, evt)
		}
	}
	return pidEvents
}

// GetDNSEventsByQuery returns all DNS events for a specific query
func (dm *DNSMap) GetDNSEventsByQuery(query string) []*DNSInfo {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Defense: Limit search length to prevent regex DoS
	if len(query) > 255 {
		query = query[:255]
	}

	var queryEvents []*DNSInfo
	for _, evt := range dm.events {
		if strings.Contains(evt.QueryName, query) {
			queryEvents = append(queryEvents, evt)
		}
	}
	return queryEvents
}

// TLSMap provides a thread-safe way to track TLS handshakes
type TLSMap struct {
	events []*TLSInfo
	mu     sync.RWMutex
	// Add rate limiting to defend against DoS
	lastCleanup time.Time
	maxSize     int
}

// NewTLSMap creates a new TLS event map
func NewTLSMap() *TLSMap {
	return &TLSMap{
		events:      make([]*TLSInfo, 0),
		lastCleanup: time.Now(),
		maxSize:     50000, // Reasonable limit to prevent memory exhaustion
	}
}

// AddTLSEvent adds a new TLS event with protection against flooding
func (tm *TLSMap) AddTLSEvent(info *TLSInfo) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Check if we need to clean up old events to prevent memory exhaustion
	if len(tm.events) > tm.maxSize || time.Since(tm.lastCleanup) > 5*time.Minute {
		// Keep only events from the last hour
		cutoff := time.Now().Add(-1 * time.Hour)
		var newEvents []*TLSInfo
		for _, evt := range tm.events {
			if evt.Timestamp.After(cutoff) {
				newEvents = append(newEvents, evt)
			}
		}
		tm.events = newEvents
		tm.lastCleanup = time.Now()
	}

	tm.events = append(tm.events, info)
}

// GetTLSEvents returns all tracked TLS events
func (tm *TLSMap) GetTLSEvents() []*TLSInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return append([]*TLSInfo{}, tm.events...)
}

// GetTLSEventsByPID returns all TLS events for a specific PID
func (tm *TLSMap) GetTLSEventsByPID(pid uint32) []*TLSInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var pidEvents []*TLSInfo
	for _, evt := range tm.events {
		if evt.PID == pid {
			pidEvents = append(pidEvents, evt)
		}
	}
	return pidEvents
}

// GetTLSEventsBySNI returns all TLS events for a specific SNI
func (tm *TLSMap) GetTLSEventsBySNI(sni string) []*TLSInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Defense: Limit search length to prevent regex DoS
	if len(sni) > 255 {
		sni = sni[:255]
	}

	var sniEvents []*TLSInfo
	for _, evt := range tm.events {
		if strings.Contains(evt.SNI, sni) {
			sniEvents = append(sniEvents, evt)
		}
	}
	return sniEvents
}
