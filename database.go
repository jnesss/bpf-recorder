package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB handles database operations
type DB struct {
	db *sql.DB
}

// ProcessRecord represents a process creation event in the database
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
	Environment string // Stored as JSON
	ContainerID string // Added container support
	UID         string // User ID
	GID         string // Group ID
}

func NewDB(dataDir string) (*DB, error) {
	fmt.Printf("Creating/opening database in: %s\n", dataDir)

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	dbPath := filepath.Join(dataDir, "process_monitor.db")
	fmt.Printf("Database path: %s\n", dbPath)

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	fmt.Println("Enabling WAL mode...")
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %v", err)
	}

	fmt.Println("Initializing process schema...")
	if err := initProcessSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %v", err)
	}

	fmt.Println("Initializing Sigma detector state schema...")
	if err := initSigmaSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %v", err)
	}

	fmt.Println("Database initialization complete!")
	return &DB{db: db}, nil
}

func initProcessSchema(db *sql.DB) error {
	fmt.Println("Creating processes table if it doesn't exist...")
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
		environment  TEXT,
        container_id TEXT,
        uid          TEXT,
        gid          TEXT
	);`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	fmt.Println("Creating indexes...")
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_pid ON processes(pid);",
		"CREATE INDEX IF NOT EXISTS idx_ppid ON processes(ppid);",
		"CREATE INDEX IF NOT EXISTS idx_timestamp ON processes(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_container ON processes(container_id);",
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

// initSigmaSchema creates the database tables needed for Sigma detection
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

// InsertProcess adds a process creation record to the database
func (db *DB) InsertProcess(record *ProcessRecord) error {
	query := `
		INSERT INTO processes (
			timestamp, pid, ppid, comm, cmdline, exe_path,
			working_dir, username, parent_comm, environment,
			container_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := db.db.Exec(query,
		record.Timestamp,
		record.PID,
		record.PPID,
		record.Comm,
		record.CmdLine,
		record.ExePath,
		record.WorkingDir,
		record.Username,
		record.ParentComm,
		record.Environment,
		record.ContainerID,
	)
	if err != nil {
		return err
	}

	id, _ := result.LastInsertId()
	fmt.Printf("+ ") // Simple visual indicator of insertion
	if id%20 == 0 {  // New line every 20 processes
		fmt.Println()
	}
	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.db.Close()
}
