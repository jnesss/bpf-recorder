package database

import (
    "database/sql"
    "fmt"
    "os"
    "path/filepath"
    "time"

    _ "github.com/mattn/go-sqlite3"
    
    "bpf-recorder/process"
    "bpf-recorder/network"
    "bpf-recorder/types"
)

// DB handles database operations
type DB struct {
    Db *sql.DB
}

// ProcessRecord represents a process event in the database
type ProcessRecord struct {
    Timestamp   time.Time
    PID         uint32
    PPID        uint32
    Comm        string
    CmdLine     string
    ExePath     string
    WorkingDir  string
    Username    string
    ParentComm  string
    ContainerID string
    UID         uint32
    GID         uint32
    ExitCode    uint32
    ExitTime    time.Time
    BinaryMD5   string
}

// NetworkRecord represents a network connection in the database
type NetworkRecord struct {
    Timestamp    time.Time
    PID          uint32
    ProcessName  string
    SrcAddr      string
    SrcPort      uint16
    DstAddr      string
    DstPort      uint16
    Protocol     string
    Operation    string
    ContainerID  string
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
		binary_md5   TEXT
	);`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create processes table: %v", err)
	}

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_pid ON processes(pid);",
		"CREATE INDEX IF NOT EXISTS idx_ppid ON processes(ppid);",
		"CREATE INDEX IF NOT EXISTS idx_timestamp ON processes(timestamp);",
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

// InsertProcess adds a process event record to the database
func (db *DB) InsertProcess(record *process.ProcessInfo) error {
    query := `
        INSERT INTO processes (
            timestamp, pid, ppid, comm, cmdline, exe_path,
            working_dir, username, parent_comm, container_id,
            uid, gid, binary_md5
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

    _, err := db.Db.Exec(query,
        record.StartTime,
        record.PID,
        record.PPID,
        record.Comm,
        record.CmdLine,
        record.ExePath,
        record.WorkingDir,
        record.Username,
        record.ParentComm,
        record.ContainerID,
        record.UID,
        record.GID,
        record.BinaryMD5)
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
        Timestamp:    time.Now(),
        PID:          info.PID,
        ProcessName:  info.ProcessName,
        SrcAddr:      info.SourceIP.String(),
        SrcPort:      info.SourcePort,
        DstAddr:      info.DestinationIP.String(),
        DstPort:      info.DestinationPort,
        Protocol:     info.Protocol,
        Operation:    getOperationString(eventType),
        ContainerID:  info.ContainerID,
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

// Close closes the database connection
func (db *DB) Close() error {
    return db.Db.Close()
}
