package main

import (
	"database/sql" // Add this for sql.ErrNoRows
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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
	Environment string    `json:"environment"`
	ContainerID string    `json:"containerId"`
}

func startWebServer(db *DB) error {
	// Debug handler that wraps other handlers and logs request details
	debugHandler := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("[%s] %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.Path)
			h(w, r)
		}
	}

	// Serve the React app
	http.HandleFunc("/", debugHandler(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Serving index.html for path: %s\n", r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

		tmpl := template.Must(template.New("index").Parse(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>BPF Process Monitor</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <script src="https://unpkg.com/react@17/umd/react.development.js"></script>
                <script src="https://unpkg.com/react-dom@17/umd/react-dom.development.js"></script>
                <script src="https://unpkg.com/babel-standalone@6/babel.min.js"></script>
                <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>
                <script>
                  // Create icons globally
                  lucide.createIcons();
                </script>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body>
                <div id="root"></div>
                <script type="text/babel" src="/app.jsx"></script>
            </body>
            </html>`))
		if err := tmpl.Execute(w, nil); err != nil {
			fmt.Printf("Error executing template: %v\n", err)
		}
	}))

	// Serve the React component code
	http.HandleFunc("/app.jsx", debugHandler(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("DEBUG: Attempting to serve app.jsx from web directory\n")
		jsxPath := filepath.Join("web", "app.jsx")

		// Check if file exists and get its info
		if info, err := os.Stat(jsxPath); err == nil {
			fmt.Printf("DEBUG: Found app.jsx, size: %d, modified: %s\n", info.Size(), info.ModTime())
		} else {
			fmt.Printf("DEBUG: Error checking app.jsx: %v\n", err)
		}

		w.Header().Set("Content-Type", "application/javascript")
		http.ServeFile(w, r, jsxPath)
	}))

	// API endpoint for process data
	http.HandleFunc("/api/processes", debugHandler(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Fetching process data from database\n")

		// Check if a specific PID was requested for the process tree
		pidParam := r.URL.Query().Get("pid")
		if pidParam != "" {
			// Fetch a specific process and its ancestors
			pid, err := strconv.Atoi(pidParam)
			if err != nil {
				http.Error(w, "Invalid PID", 400)
				return
			}

			processes, err := fetchProcessTree(db, uint32(pid))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(processes)
			return
		}

		// Default: fetch recent processes
		rows, err := db.db.Query(`
            SELECT 
                id, timestamp, pid, ppid, comm, cmdline, exe_path,
                working_dir, username, parent_comm, environment, container_id
            FROM processes 
            ORDER BY timestamp DESC 
            LIMIT 100
        `)
		if err != nil {
			fmt.Printf("Database query error: %v\n", err)
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()

		var processes []ProcessRow
		for rows.Next() {
			var p ProcessRow
			err := rows.Scan(
				&p.ID, &p.Timestamp, &p.PID, &p.PPID, &p.Comm,
				&p.CmdLine, &p.ExePath, &p.WorkingDir, &p.Username,
				&p.ParentComm, &p.Environment, &p.ContainerID,
			)
			if err != nil {
				fmt.Printf("Error scanning row: %v\n", err)
				http.Error(w, err.Error(), 500)
				return
			}
			processes = append(processes, p)
		}

		fmt.Printf("Returning %d processes\n", len(processes))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(processes)
	}))

	fmt.Printf("Starting web server on :8080\n")
	return http.ListenAndServe(":8080", nil)
}

// Helper function to fetch a process and its ancestors
func fetchProcessTree(db *DB, pid uint32) ([]ProcessRow, error) {
	fmt.Printf("Fetching process tree for PID %d\n", pid)

	var processes []ProcessRow
	var pidList []uint32
	currentPid := pid

	// Add the current PID to our list
	pidList = append(pidList, currentPid)

	// First, build a list of PIDs we need to fetch (the process and all its ancestors)
	tempPid := currentPid
	for tempPid > 0 {
		// Find the parent PID
		var ppid uint32
		err := db.db.QueryRow("SELECT ppid FROM processes WHERE pid = ? ORDER BY timestamp DESC LIMIT 1", tempPid).Scan(&ppid)
		if err != nil {
			if err == sql.ErrNoRows {
				// No more ancestors found, break the loop
				break
			}
			return nil, err
		}

		// Add the parent PID to our list
		if ppid > 0 {
			pidList = append(pidList, ppid)
		}

		// Move up to the parent for the next iteration
		tempPid = ppid

		// Safety check to prevent infinite loops
		if len(pidList) > 100 {
			break
		}
	}

	// Next, add child processes
	rows, err := db.db.Query("SELECT DISTINCT pid FROM processes WHERE ppid = ? ORDER BY timestamp DESC", pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var childPid uint32
		if err := rows.Scan(&childPid); err != nil {
			return nil, err
		}
		pidList = append(pidList, childPid)
	}

	fmt.Printf("PIDs to fetch: %v\n", pidList)

	// Now fetch all processes in the tree
	if len(pidList) > 0 {
		// Convert PID list to a string for the IN clause
		var placeholders []string
		var args []interface{}
		for _, p := range pidList {
			placeholders = append(placeholders, "?")
			args = append(args, p)
		}

		query := fmt.Sprintf(`
            SELECT 
                id, timestamp, pid, ppid, comm, cmdline, exe_path,
                working_dir, username, parent_comm, environment, container_id
            FROM processes 
            WHERE pid IN (%s)
            ORDER BY timestamp DESC
        `, strings.Join(placeholders, ","))

		rows, err := db.db.Query(query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		// Build a map to keep only the most recent entry for each PID
		pidMap := make(map[uint32]ProcessRow)
		for rows.Next() {
			var p ProcessRow
			err := rows.Scan(
				&p.ID, &p.Timestamp, &p.PID, &p.PPID, &p.Comm,
				&p.CmdLine, &p.ExePath, &p.WorkingDir, &p.Username,
				&p.ParentComm, &p.Environment, &p.ContainerID,
			)
			if err != nil {
				return nil, err
			}

			// Only keep the most recent entry for each PID
			if existing, ok := pidMap[p.PID]; !ok || p.Timestamp.After(existing.Timestamp) {
				pidMap[p.PID] = p
			}
		}

		// Convert map back to slice
		for _, p := range pidMap {
			processes = append(processes, p)
		}
	}

	return processes, nil
}
