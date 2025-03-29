package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
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
