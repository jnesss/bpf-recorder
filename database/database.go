package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/jnesss/bpf-recorder/network"
	"github.com/jnesss/bpf-recorder/process"
	"github.com/jnesss/bpf-recorder/types"
)

// DB handles database operations
type DB struct {
	Db *sql.DB
}

// ProcessRecord represents a process event in the database
type ProcessRecord struct {
	Timestamp     time.Time
	PID           uint32
	PPID          uint32
	Comm          string
	CmdLine       string
	ExePath       string
	WorkingDir    string
	Username      string
	ParentComm    string
	ContainerID   string
	UID           uint32
	GID           uint32
	ExitCode      uint32
	ExitTime      time.Time
	BinaryMD5     string
	Environment   []string
	FileDescCount int
	CPUUsage      float64
	MemoryUsage   uint64
	MemoryPercent float64
	ThreadCount   int
	OpenFiles     []string
	DirHistory    []string
}

// NetworkRecord represents a network connection in the database
type NetworkRecord struct {
	Timestamp   time.Time
	PID         uint32
	ProcessName string
	SrcAddr     string
	SrcPort     uint16
	DstAddr     string
	DstPort     uint16
	Protocol    string
	Operation   string
	ContainerID string
}

// DNSRecord represents a DNS query or response in the database
type DNSRecord struct {
	Timestamp     time.Time
	PID           uint32
	ProcessName   string
	SrcAddr       string
	SrcPort       uint16
	DstAddr       string
	DstPort       uint16
	ContainerID   string
	TransactionID uint16
	QueryName     string
	QueryType     uint16
	IsResponse    bool
	Flags         uint16
	QuestionCount uint16
	AnswerCount   uint16
}

// TLSRecord represents a TLS handshake event in the database
type TLSRecord struct {
	Timestamp     time.Time
	PID           uint32
	ProcessName   string
	SrcAddr       string
	SrcPort       uint16
	DstAddr       string
	DstPort       uint16
	ContainerID   string
	TLSVersion    uint16
	HandshakeType uint8
	SNI           string
}

func NewDB(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	dbPath := filepath.Join(dataDir, "process_monitor.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %v", err)
	}

	if err := initProcessSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize process schema: %v", err)
	}

	if err := initNetworkSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize network schema: %v", err)
	}

	if err := initSigmaSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize sigma schema: %v", err)
	}

	if err := initDNSSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize DNS schema: %v", err)
	}

	if err := initTLSSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize TLS schema: %v", err)
	}

	return &DB{Db: db}, nil
}

func initProcessSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS processes (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp    DATETIME NOT NULL,
		pid          INTEGER NOT NULL,
		ppid         INTEGER NOT NULL,
		comm         TEXT NOT NULL,
		cmdline      TEXT,
		exe_path     TEXT,
		working_dir  TEXT,
		username     TEXT,
		parent_comm  TEXT,
		container_id TEXT,
		uid          INTEGER,
		gid          INTEGER,
		exit_code    INTEGER,
		exit_time    DATETIME,
		binary_md5   TEXT,
        environment     TEXT,           -- JSON array of environment variables
        file_desc_count INTEGER,        -- Number of open file descriptors
        cpu_usage       REAL,           -- CPU usage percentage
        memory_usage    INTEGER,        -- Memory usage in bytes
        memory_percent  REAL,           -- Memory usage percentage
        thread_count    INTEGER,        -- Number of threads
        open_files      TEXT,           -- JSON array of open files
        dir_history     TEXT            -- JSON array of working directory history
	);`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create processes table: %v", err)
	}

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_pid ON processes(pid);",
		"CREATE INDEX IF NOT EXISTS idx_ppid ON processes(ppid);",
		"CREATE INDEX IF NOT EXISTS idx_timestamp ON processes(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_cpu_usage ON processes(cpu_usage);",
		"CREATE INDEX IF NOT EXISTS idx_memory_usage ON processes(memory_usage);",
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

func initNetworkSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS network_connections (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp    DATETIME NOT NULL,
		pid          INTEGER NOT NULL,
		process_name TEXT NOT NULL,
		src_addr     TEXT,
		src_port     INTEGER,
		dst_addr     TEXT,
		dst_port     INTEGER,
		protocol     TEXT,
		operation    TEXT,
		container_id TEXT
	);`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create network table: %v", err)
	}

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_net_pid ON network_connections(pid);",
		"CREATE INDEX IF NOT EXISTS idx_net_timestamp ON network_connections(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_net_dst ON network_connections(dst_addr, dst_port);",
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

func initSigmaSchema(db *sql.DB) error {
	schema := `
    CREATE TABLE IF NOT EXISTS detector_state (
        id INTEGER PRIMARY KEY,
        event_type TEXT NOT NULL,
        last_id INTEGER NOT NULL,
        last_processed_time DATETIME NOT NULL,
        rule_count INTEGER DEFAULT 0,
        match_count INTEGER DEFAULT 0,
        updated_at DATETIME NOT NULL,
        UNIQUE(event_type)
    );

    CREATE TABLE IF NOT EXISTS sigma_matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        process_id INTEGER,
        process_name TEXT,
        command_line TEXT,
        parent_process_name TEXT,
        parent_command_line TEXT,
        username TEXT,
        timestamp DATETIME NOT NULL,
        severity TEXT NOT NULL,
        status TEXT DEFAULT 'new' NOT NULL,
        match_details TEXT,
        event_data TEXT,
        created_at DATETIME NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sigma_matches_rule_id ON sigma_matches(rule_id);
    CREATE INDEX IF NOT EXISTS idx_sigma_matches_timestamp ON sigma_matches(timestamp);
    CREATE INDEX IF NOT EXISTS idx_sigma_matches_status ON sigma_matches(status);
    CREATE INDEX IF NOT EXISTS idx_sigma_matches_event_id ON sigma_matches(event_id);`

	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create Sigma tables: %v", err)
	}

	return nil
}

// initDNSSchema creates the DNS table in the database
func initDNSSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS dns_events (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp    DATETIME NOT NULL,
		pid          INTEGER NOT NULL,
		process_name TEXT NOT NULL,
		src_addr     TEXT,
		src_port     INTEGER,
		dst_addr     TEXT,
		dst_port     INTEGER,
		transaction_id INTEGER,
		query_name   TEXT,
		query_type   INTEGER,
		is_response  BOOLEAN,
		flags        INTEGER,
		question_count INTEGER,
		answer_count INTEGER,
		container_id TEXT
	);`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create dns_events table: %v", err)
	}

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_dns_pid ON dns_events(pid);",
		"CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_events(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_dns_query ON dns_events(query_name);",
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

// initTLSSchema creates the TLS table in the database
func initTLSSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS tls_events (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp    DATETIME NOT NULL,
		pid          INTEGER NOT NULL,
		process_name TEXT NOT NULL,
		src_addr     TEXT,
		src_port     INTEGER,
		dst_addr     TEXT,
		dst_port     INTEGER,
		tls_version  INTEGER,
		handshake_type INTEGER,
		sni          TEXT,
		container_id TEXT
	);`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create tls_events table: %v", err)
	}

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_tls_pid ON tls_events(pid);",
		"CREATE INDEX IF NOT EXISTS idx_tls_timestamp ON tls_events(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_tls_sni ON tls_events(sni);",
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

// InsertProcess adds a process event record to the database
func (db *DB) InsertProcess(record *process.ProcessInfo) error {
	// Gather all data under lock
	record.Mu.RLock()
	insertData := struct {
		startTime      time.Time
		pid            uint32
		ppid           uint32
		comm           string
		cmdLine        string
		exePath        string
		workingDir     string
		username       string
		parentComm     string
		containerID    string
		uid            uint32
		gid            uint32
		binaryMD5      string
		environment    []string
		workingDirHist []string
		stats          *process.ProcessStats
	}{
		startTime:      record.StartTime,
		pid:            record.PID,
		ppid:           record.PPID,
		comm:           record.Comm,
		cmdLine:        record.CmdLine,
		exePath:        record.ExePath,
		workingDir:     record.WorkingDir,
		username:       record.Username,
		parentComm:     record.ParentComm,
		containerID:    record.ContainerID,
		uid:            record.UID,
		gid:            record.GID,
		binaryMD5:      record.BinaryMD5,
		environment:    append([]string{}, record.Environment...),
		workingDirHist: append([]string{}, record.WorkingDirHistory...),
		stats:          record.Stats,
	}
	record.Mu.RUnlock()

	// Now do all JSON marshaling and database operations without holding the lock
	envJSON, err := json.Marshal(insertData.environment)
	if err != nil {
		return fmt.Errorf("failed to marshal environment: %v", err)
	}

	dirHistoryJSON, err := json.Marshal(insertData.workingDirHist)
	if err != nil {
		return fmt.Errorf("failed to marshal directory history: %v", err)
	}

	// Get stats values if available
	var (
		fileDescCount int
		cpuUsage      float64
		memoryUsage   uint64
		memoryPercent float64
		threadCount   int
		openFiles     []string
	)

	if insertData.stats != nil {
		insertData.stats.Mu.RLock()
		fileDescCount = insertData.stats.FileDescCount
		cpuUsage = insertData.stats.CPUUsage
		memoryUsage = insertData.stats.MemoryUsage
		memoryPercent = insertData.stats.MemoryPercent
		threadCount = insertData.stats.ThreadCount
		openFiles = append([]string{}, insertData.stats.OpenFiles...)
		insertData.stats.Mu.RUnlock()
	}

	openFilesJSON, err := json.Marshal(openFiles)
	if err != nil {
		return fmt.Errorf("failed to marshal open files: %v", err)
	}

	query := `
        INSERT INTO processes (
            timestamp, pid, ppid, comm, cmdline, exe_path,
            working_dir, username, parent_comm, container_id,
            uid, gid, binary_md5,
            environment, file_desc_count, cpu_usage,
            memory_usage, memory_percent, thread_count,
            open_files, dir_history
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = db.Db.Exec(query,
		insertData.startTime,
		insertData.pid,
		insertData.ppid,
		insertData.comm,
		insertData.cmdLine,
		insertData.exePath,
		insertData.workingDir,
		insertData.username,
		insertData.parentComm,
		insertData.containerID,
		insertData.uid,
		insertData.gid,
		insertData.binaryMD5,
		string(envJSON),
		fileDescCount,
		cpuUsage,
		memoryUsage,
		memoryPercent,
		threadCount,
		string(openFilesJSON),
		string(dirHistoryJSON))

	return err
}

// UpdateProcessStats updates the stats for a running process
func (db *DB) UpdateProcessStats(pid uint32, stats *process.ProcessStats) error {
	// Gather all data under lock
	stats.Mu.RLock()
	updateData := struct {
		cpuUsage      float64
		memoryUsage   uint64
		memoryPercent float64
		threadCount   int
		fileDescCount int
		openFiles     []string
	}{
		cpuUsage:      stats.CPUUsage,
		memoryUsage:   stats.MemoryUsage,
		memoryPercent: stats.MemoryPercent,
		threadCount:   stats.ThreadCount,
		fileDescCount: stats.FileDescCount,
		openFiles:     append([]string{}, stats.OpenFiles...),
	}
	stats.Mu.RUnlock()

	// Do JSON marshaling and database operations without holding the lock
	openFilesJSON, err := json.Marshal(updateData.openFiles)
	if err != nil {
		return fmt.Errorf("failed to marshal open files: %v", err)
	}

	query := `
        UPDATE processes 
        SET cpu_usage = ?,
            memory_usage = ?,
            memory_percent = ?,
            thread_count = ?,
            file_desc_count = ?,
            open_files = ?
        WHERE pid = ? 
        AND exit_time IS NULL`

	_, err = db.Db.Exec(query,
		updateData.cpuUsage,
		updateData.memoryUsage,
		updateData.memoryPercent,
		updateData.threadCount,
		updateData.fileDescCount,
		string(openFilesJSON),
		pid)

	return err
}

func (db *DB) UpdateProcessExit(pid uint32, exitCode uint32, exitTime time.Time) error {
	query := `
        UPDATE processes
        SET exit_code = ?,
            exit_time = ?
        WHERE pid = ?
        AND exit_time IS NULL`

	_, err := db.Db.Exec(query, exitCode, exitTime, pid)
	return err
}

// InsertNetworkConnection adds a network connection record to the database
func (db *DB) InsertNetworkConnection(info *network.ConnectionInfo, eventType uint32) error {
	record := &NetworkRecord{
		Timestamp:   time.Now(),
		PID:         info.PID,
		ProcessName: info.ProcessName,
		SrcAddr:     info.SourceIP.String(),
		SrcPort:     info.SourcePort,
		DstAddr:     info.DestinationIP.String(),
		DstPort:     info.DestinationPort,
		Protocol:    info.Protocol,
		Operation:   getOperationString(eventType),
		ContainerID: info.ContainerID,
	}

	query := `
        INSERT INTO network_connections (
            timestamp, pid, process_name, src_addr, src_port,
            dst_addr, dst_port, protocol, operation, container_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Db.Exec(query,
		record.Timestamp,
		record.PID,
		record.ProcessName,
		record.SrcAddr,
		record.SrcPort,
		record.DstAddr,
		record.DstPort,
		record.Protocol,
		record.Operation,
		record.ContainerID,
	)
	return err
}

func getOperationString(eventType uint32) string {
	switch eventType {
	case types.EventNetConnect:
		return "connect"
	case types.EventNetAccept:
		return "accept"
	case types.EventNetBind:
		return "bind"
	default:
		return "unknown"
	}
}

// InsertDNSEvent adds a DNS event record to the database
func (db *DB) InsertDNSEvent(info *network.DNSInfo) error {
	record := &DNSRecord{
		Timestamp:     info.Timestamp,
		PID:           info.PID,
		ProcessName:   info.ProcessName,
		SrcAddr:       info.SourceIP.String(),
		SrcPort:       info.SourcePort,
		DstAddr:       info.DestinationIP.String(),
		DstPort:       info.DestinationPort,
		ContainerID:   info.ContainerID,
		TransactionID: info.TransactionID,
		QueryName:     info.QueryName,
		QueryType:     info.QueryType,
		IsResponse:    info.IsResponse,
		Flags:         info.Flags,
		QuestionCount: info.QuestionCount,
		AnswerCount:   info.AnswerCount,
	}

	query := `
        INSERT INTO dns_events (
            timestamp, pid, process_name, src_addr, src_port,
            dst_addr, dst_port, transaction_id, query_name, query_type,
            is_response, flags, question_count, answer_count, container_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Db.Exec(query,
		record.Timestamp,
		record.PID,
		record.ProcessName,
		record.SrcAddr,
		record.SrcPort,
		record.DstAddr,
		record.DstPort,
		record.TransactionID,
		record.QueryName,
		record.QueryType,
		record.IsResponse,
		record.Flags,
		record.QuestionCount,
		record.AnswerCount,
		record.ContainerID,
	)
	return err
}

// InsertTLSEvent adds a TLS event record to the database
func (db *DB) InsertTLSEvent(info *network.TLSInfo) error {
	record := &TLSRecord{
		Timestamp:     info.Timestamp,
		PID:           info.PID,
		ProcessName:   info.ProcessName,
		SrcAddr:       info.SourceIP.String(),
		SrcPort:       info.SourcePort,
		DstAddr:       info.DestinationIP.String(),
		DstPort:       info.DestinationPort,
		ContainerID:   info.ContainerID,
		TLSVersion:    info.TLSVersion,
		HandshakeType: info.HandshakeType,
		SNI:           info.SNI,
	}

	query := `
        INSERT INTO tls_events (
            timestamp, pid, process_name, src_addr, src_port,
            dst_addr, dst_port, tls_version, handshake_type, sni, container_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Db.Exec(query,
		record.Timestamp,
		record.PID,
		record.ProcessName,
		record.SrcAddr,
		record.SrcPort,
		record.DstAddr,
		record.DstPort,
		record.TLSVersion,
		record.HandshakeType,
		record.SNI,
		record.ContainerID,
	)
	return err
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.Db.Close()
}
