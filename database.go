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

	fmt.Println("Initializing schema...")
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %v", err)
	}

	fmt.Println("Database initialization complete!")
	return &DB{db: db}, nil
}

func initSchema(db *sql.DB) error {
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
		container_id TEXT
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

func initSchema(db *sql.DB) error {
	// Create table
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
		container_id TEXT
	);`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	// Create indexes
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
