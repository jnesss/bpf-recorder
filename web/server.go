package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sigmago "github.com/bradleyjkemp/sigma-go"

	"github.com/jnesss/bpf-recorder/binary"
	"github.com/jnesss/bpf-recorder/sigma"
)

type Server struct {
	db            *sql.DB
	sigmaDetector *sigma.Detector
	binaryCache   *binary.Cache
	listenAddr    string
}

func NewServer(db *sql.DB, sigmaDetector *sigma.Detector, binaryCache *binary.Cache, listenAddr string) *Server {
	return &Server{
		db:            db,
		sigmaDetector: sigmaDetector,
		binaryCache:   binaryCache,
		listenAddr:    listenAddr,
	}
}

func (s *Server) Start(ctx context.Context) error {
	// Debug handler that wraps other handlers and logs request details
	debugHandler := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("[%s] %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.Path)
			h(w, r)
		}
	}

	// Register routes
	http.HandleFunc("/", debugHandler(s.handleIndex))
	http.HandleFunc("/app.jsx", debugHandler(s.handleAppJSX))
	http.HandleFunc("/api/processes", debugHandler(s.handleProcesses))
	http.HandleFunc("/api/network", debugHandler(s.handleNetworkConnections))
	http.HandleFunc("/api/binaries", debugHandler(s.handleBinaries))

	// Add Sigma routes if detector is available
	if s.sigmaDetector != nil {
		http.HandleFunc("/api/sigma/rules", debugHandler(s.handleSigmaRules))
		http.HandleFunc("/api/sigma/rules/toggle/", debugHandler(s.handleSigmaRuleToggle))
		http.HandleFunc("/api/sigma/rules/upload", debugHandler(s.handleSigmaRuleUpload))
		http.HandleFunc("/api/sigma/matches", debugHandler(s.handleSigmaMatchesList))
		http.HandleFunc("/api/sigma/matches/", debugHandler(s.handleSigmaMatchOperation))
	}

	// Create server instance
	srv := &http.Server{
		Addr:    s.listenAddr,
		Handler: http.DefaultServeMux,
	}

	fmt.Printf("Starting web server on %s\n", s.listenAddr)

	// Graceful shutdown goroutine
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Stop() error {
	// Nothing to do yet, but interface allows for future cleanup
	return nil
}

// handleIndex serves the main HTML page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Serving index.html for path: %s\n", r.URL.Path)
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	tmpl := template.Must(template.New("index").Parse(indexTemplate))
	if err := tmpl.Execute(w, nil); err != nil {
		fmt.Printf("Error executing template: %v\n", err)
	}
}

// handleAppJSX serves the React component code
func (s *Server) handleAppJSX(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	http.ServeFile(w, r, filepath.Join("web", "app.jsx"))
}

// handleProcesses returns an http.HandlerFunc for process-related requests
func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Fetching process data from database\n")

	// Check if a specific PID was requested for the process tree
	pidParam := r.URL.Query().Get("pid")
	idParam := r.URL.Query().Get("id") // Added parameter for table ID

	if pidParam != "" {
		s.handleProcessTree(w, r, pidParam)
		return
	}

	// If a specific ID was requested
	if idParam != "" {
		s.handleProcessById(w, r, idParam)
		return
	}

	// Default: fetch recent processes
	s.handleRecentProcesses(w, r)
}

func (s *Server) handleNetworkConnections(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`
        SELECT 
            id, timestamp, pid, process_name, 
            src_addr, src_port, dst_addr, dst_port,
            protocol, operation, container_id
        FROM network_connections 
        ORDER BY timestamp DESC 
        LIMIT 1000
    `)
	if err != nil {
		fmt.Printf("Database query error: %v\n", err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var connections []NetworkRow
	for rows.Next() {
		var conn NetworkRow
		err := rows.Scan(
			&conn.ID, &conn.Timestamp, &conn.PID, &conn.ProcessName,
			&conn.SrcAddr, &conn.SrcPort, &conn.DstAddr, &conn.DstPort,
			&conn.Protocol, &conn.Operation, &conn.ContainerID,
		)
		if err != nil {
			fmt.Printf("Error scanning row: %v\n", err)
			http.Error(w, err.Error(), 500)
			return
		}
		connections = append(connections, conn)
	}

	fmt.Printf("Returning %d network connections\n", len(connections))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connections)
}

// handleProcessTree handles fetching a process tree for a specific PID
func (s *Server) handleProcessTree(w http.ResponseWriter, r *http.Request, pidParam string) {
	pid, err := strconv.Atoi(pidParam)
	if err != nil {
		http.Error(w, "Invalid PID", 400)
		return
	}

	processes, err := s.fetchProcessTree(uint32(pid))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(processes)
}

// handleProcessById handles fetching a process by its database ID
func (s *Server) handleProcessById(w http.ResponseWriter, r *http.Request, idParam string) {
	id, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", 400)
		return
	}

	//  get processes around this ID
	query := `
        SELECT
            id, timestamp, pid, ppid, comm, cmdline, exe_path,
            working_dir, username, parent_comm, container_id, binary_md5
        FROM processes
        WHERE id BETWEEN ? AND ?
        ORDER BY id DESC
    `

	// Get 50 before and 50 after
	minId := id - 50
	if minId < 0 {
		minId = 0
	}
	maxId := id + 50

	rows, err := s.db.Query(query, minId, maxId)
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
			&p.ParentComm, &p.ContainerID, &p.BinaryMD5,
		)
		if err != nil {
			fmt.Printf("Error scanning row: %v\n", err)
			http.Error(w, err.Error(), 500)
			return
		}
		processes = append(processes, p)
	}

	// Make sure to verify the selected process exists in our results
	selectedExists := false
	for _, p := range processes {
		if p.ID == id {
			selectedExists = true
			break
		}
	}

	// If the selected process wasn't found in our results, try to fetch it specifically
	if !selectedExists {
		query = `
            SELECT
                id, timestamp, pid, ppid, comm, cmdline, exe_path,
                working_dir, username, parent_comm, container_id, binary_md5
            FROM processes
            WHERE id = ?
        `

		var p ProcessRow
		err = s.db.QueryRow(query, id).Scan(
			&p.ID, &p.Timestamp, &p.PID, &p.PPID, &p.Comm,
			&p.CmdLine, &p.ExePath, &p.WorkingDir, &p.Username,
			&p.ParentComm, &p.ContainerID, &p.BinaryMD5,
		)

		if err == nil {
			processes = append(processes, p)
		} else if err != sql.ErrNoRows {
			// Only return an error if it's not just a missing row
			fmt.Printf("Error fetching selected process: %v\n", err)
		}
	}

	// Include the selected ID in the response
	result := map[string]interface{}{
		"processes":  processes,
		"selectedId": id,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleRecentProcesses handles fetching recent processes
func (s *Server) handleRecentProcesses(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`
            SELECT
                id, timestamp, pid, ppid, comm, 
                cmdline, exe_path, working_dir, username, 
                parent_comm, container_id, binary_md5,
                exit_time,
                cpu_usage, memory_usage, memory_percent, thread_count
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
			&p.ParentComm, &p.ContainerID, &p.BinaryMD5,
			&p.ExitTime,
			&p.CPUUsage, &p.MemoryUsage, &p.MemoryPercent, &p.ThreadCount,
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
}

// handleBinaries returns an http.HandlerFunc for binary-related requests
func (s *Server) handleBinaries(w http.ResponseWriter, r *http.Request) {
	// Extract hash from query parameter
	hash := r.URL.Query().Get("md5")

	if hash == "" {
		http.Error(w, "Missing md5 parameter", 400)
		return
	}

	// Check if binary exists
	binPath := s.binaryCache.GetBinaryPath(hash)
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		http.Error(w, "Binary not found", 404)
		return
	}

	// Serve the binary file
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.bin", hash))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, binPath)
}

// handleSigmaRules returns an http.HandlerFunc for Sigma rule listing
func (s *Server) handleSigmaRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enabledDir := filepath.Join(s.sigmaDetector.RulesDir, "enabled_rules")
	disabledDir := filepath.Join(s.sigmaDetector.RulesDir, "disabled_rules")

	// Create directories if they don't exist
	for _, dir := range []string{enabledDir, disabledDir} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				http.Error(w, fmt.Sprintf("Error creating directory: %v", err), http.StatusInternalServerError)
				return
			}
		}
	}

	// Collect all rules
	var rules []map[string]interface{}

	// Read enabled rules
	enabledRules, err := s.readRulesFromDir(enabledDir, true)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading enabled rules: %v", err), http.StatusInternalServerError)
		return
	}
	rules = append(rules, enabledRules...)

	// Read disabled rules
	disabledRules, err := s.readRulesFromDir(disabledDir, false)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading disabled rules: %v", err), http.StatusInternalServerError)
		return
	}
	rules = append(rules, disabledRules...)

	// Return all rules as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// readRulesFromDir reads and parses Sigma rules from a directory
func (s *Server) readRulesFromDir(dir string, enabled bool) ([]map[string]interface{}, error) {
	var rules []map[string]interface{}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist, return empty slice
			return rules, nil
		}
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".yml") || strings.HasSuffix(file.Name(), ".yaml")) {
			filePath := filepath.Join(dir, file.Name())

			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				// Skip files that can't be read
				continue
			}

			// Use sigma-go to parse the rule
			rule, err := sigmago.ParseRule(content)
			if err != nil {
				// Skip files that can't be parsed
				continue
			}

			// Convert to a map for JSON serialization
			ruleMap := map[string]interface{}{
				"id":          rule.ID,
				"title":       rule.Title,
				"description": rule.Description,
				"level":       rule.Level,
				"author":      rule.Author,
				"tags":        rule.Tags,
				"references":  rule.References,
				"detection":   rule.Detection,
				"filepath":    filePath,
				"filename":    file.Name(),
				"enabled":     enabled,
				"yaml":        string(content),
			}
			// For date information, check if it exists in AdditionalFields
			if date, ok := rule.AdditionalFields["date"]; ok {
				ruleMap["date"] = date
			}
			if modified, ok := rule.AdditionalFields["modified"]; ok {
				ruleMap["modified"] = modified
			}

			rules = append(rules, ruleMap)
		}
	}

	return rules, nil
}

// handleSigmaRuleToggle returns an http.HandlerFunc for toggling Sigma rules
func (s *Server) handleSigmaRuleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract rule ID from path by removing the prefix
	ruleID := strings.TrimPrefix(r.URL.Path, "/api/sigma/rules/toggle/")
	if ruleID == "" {
		http.Error(w, "Rule ID required", http.StatusBadRequest)
		return
	}

	fmt.Printf("Toggling rule: %s\n", ruleID)

	// Toggle rule's enabled status
	enabledDir := filepath.Join(s.sigmaDetector.RulesDir, "enabled_rules")
	disabledDir := filepath.Join(s.sigmaDetector.RulesDir, "disabled_rules")

	// Find the rule file
	var sourceDir, targetDir string
	var ruleEnabled bool

	// Check if rule is in enabled directory
	enabledFiles, _ := ioutil.ReadDir(enabledDir)
	for _, file := range enabledFiles {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".yml") || strings.HasSuffix(file.Name(), ".yaml")) {
			filePath := filepath.Join(enabledDir, file.Name())
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				continue
			}

			rule, err := sigmago.ParseRule(content)
			if err != nil {
				continue
			}

			if rule.ID == ruleID {
				sourceDir = enabledDir
				targetDir = disabledDir
				ruleEnabled = false
				break
			}
		}
	}

	// If not found in enabled, check disabled
	if sourceDir == "" {
		disabledFiles, _ := ioutil.ReadDir(disabledDir)
		for _, file := range disabledFiles {
			if !file.IsDir() && (strings.HasSuffix(file.Name(), ".yml") || strings.HasSuffix(file.Name(), ".yaml")) {
				filePath := filepath.Join(disabledDir, file.Name())
				content, err := ioutil.ReadFile(filePath)
				if err != nil {
					continue
				}

				rule, err := sigmago.ParseRule(content)
				if err != nil {
					continue
				}

				if rule.ID == ruleID {
					sourceDir = disabledDir
					targetDir = enabledDir
					ruleEnabled = true
					break
				}
			}
		}
	}

	if sourceDir == "" {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}

	// Find the file
	var filePath, fileName string
	files, _ := ioutil.ReadDir(sourceDir)
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".yml") || strings.HasSuffix(file.Name(), ".yaml")) {
			path := filepath.Join(sourceDir, file.Name())
			content, err := ioutil.ReadFile(path)
			if err != nil {
				continue
			}

			rule, err := sigmago.ParseRule(content)
			if err != nil {
				continue
			}

			if rule.ID == ruleID {
				filePath = path
				fileName = file.Name()
				break
			}
		}
	}

	if filePath == "" {
		http.Error(w, "Rule file not found", http.StatusNotFound)
		return
	}

	// Move file from source to target directory
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading rule file: %v", err), http.StatusInternalServerError)
		return
	}

	targetPath := filepath.Join(targetDir, fileName)
	err = ioutil.WriteFile(targetPath, content, 0644)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error writing rule file: %v", err), http.StatusInternalServerError)
		return
	}

	// Remove original file
	err = os.Remove(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error removing original rule file: %v", err), http.StatusInternalServerError)
		return
	}

	// No need to explicitly call ReloadRules since the file watcher will detect the changes
	// and trigger a reload automatically

	// Parse rule for response
	rule, _ := sigmago.ParseRule(content)

	// Return updated rule
	ruleMap := map[string]interface{}{
		"id":          rule.ID,
		"title":       rule.Title,
		"description": rule.Description,
		"level":       rule.Level,
		"author":      rule.Author,
		"tags":        rule.Tags,
		"references":  rule.References,
		"detection":   rule.Detection,
		"filepath":    targetPath,
		"filename":    fileName,
		"enabled":     ruleEnabled,
	}

	// For date information, check if it exists in AdditionalFields
	if date, ok := rule.AdditionalFields["date"]; ok {
		ruleMap["date"] = date
	}
	if modified, ok := rule.AdditionalFields["modified"]; ok {
		ruleMap["modified"] = modified
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ruleMap)
}

// handleSigmaRuleUpload returns an http.HandlerFunc for uploading Sigma rules
func (s *Server) handleSigmaRuleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var request struct {
		Content  string `json:"content"`
		Filename string `json:"filename"`
		Enabled  bool   `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate data
	if request.Content == "" || request.Filename == "" {
		http.Error(w, "Content and filename are required", http.StatusBadRequest)
		return
	}

	// Make sure filename has valid extension
	if !strings.HasSuffix(request.Filename, ".yml") && !strings.HasSuffix(request.Filename, ".yaml") {
		http.Error(w, "Filename must have .yml or .yaml extension", http.StatusBadRequest)
		return
	}

	// Try to parse the rule to validate it
	rule, err := sigmago.ParseRule([]byte(request.Content))
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid rule format: %v", err), http.StatusBadRequest)
		return
	}

	// Determine target directory
	var targetDir string
	if request.Enabled {
		targetDir = filepath.Join(s.sigmaDetector.RulesDir, "enabled_rules")
	} else {
		targetDir = filepath.Join(s.sigmaDetector.RulesDir, "disabled_rules")
	}

	// Ensure the directory exists
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create directory: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Write the file
	filePath := filepath.Join(targetDir, request.Filename)
	err = ioutil.WriteFile(filePath, []byte(request.Content), 0644)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to write file: %v", err), http.StatusInternalServerError)
		return
	}

	// No need to explicitly call ReloadRules since the file watcher will detect the changes
	// and trigger a reload automatically

	// Return success with rule info
	ruleMap := map[string]interface{}{
		"id":          rule.ID,
		"title":       rule.Title,
		"description": rule.Description,
		"level":       rule.Level,
		"author":      rule.Author,
		"tags":        rule.Tags,
		"references":  rule.References,
		"detection":   rule.Detection,
		"filepath":    filePath,
		"filename":    request.Filename,
		"enabled":     request.Enabled,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ruleMap)
}

// handleSigmaMatchesList returns an http.HandlerFunc for listing Sigma matches
func (s *Server) handleSigmaMatchesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters
	filters := map[string]string{
		"status":   r.URL.Query().Get("status"),
		"severity": r.URL.Query().Get("severity"),
		"rule":     r.URL.Query().Get("rule"),
	}

	fmt.Printf("Fetching matches with filters: %v\n", filters)

	// Get matches from detector with filters
	matches, err := s.sigmaDetector.GetMatches(100, 0, filters)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching matches: %v", err), http.StatusInternalServerError)
		return
	}

	// Return as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(matches)
}

// handleSigmaMatchOperation returns an http.HandlerFunc for operations on individual matches
func (s *Server) handleSigmaMatchOperation(w http.ResponseWriter, r *http.Request) {
	// Extract match ID from URL path - /api/sigma/matches/{id}
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		http.Error(w, "Invalid match ID", http.StatusBadRequest)
		return
	}

	matchID, err := strconv.ParseInt(pathParts[4], 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid match ID: %v", err), http.StatusBadRequest)
		return
	}

	// Handle based on HTTP method
	switch r.Method {
	case http.MethodGet:
		// Get a specific match (not implemented yet)
		http.Error(w, "Getting individual match not implemented", http.StatusNotImplemented)
	case http.MethodPost:
		// Update match status
		var request struct {
			Status string `json:"status"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		fmt.Printf("Updating match %d status to: %s\n", matchID, request.Status)

		if err := s.sigmaDetector.UpdateMatchStatus(matchID, request.Status); err != nil {
			http.Error(w, fmt.Sprintf("Error updating match status: %v", err), http.StatusInternalServerError)
			return
		}

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     matchID,
			"status": request.Status,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// fetchProcessTree fetches a process and its ancestors
func (s *Server) fetchProcessTree(pid uint32) ([]ProcessRow, error) {
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
		err := s.db.QueryRow("SELECT ppid FROM processes WHERE pid = ? ORDER BY timestamp DESC LIMIT 1", tempPid).Scan(&ppid)
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
	rows, err := s.db.Query("SELECT DISTINCT pid FROM processes WHERE ppid = ? ORDER BY timestamp DESC", pid)
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
				working_dir, username, parent_comm, container_id, binary_md5
			FROM processes
			WHERE pid IN (%s)
			ORDER BY timestamp DESC
		`, strings.Join(placeholders, ","))

		rows, err := s.db.Query(query, args...)
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
				&p.ParentComm, &p.ContainerID, &p.BinaryMD5,
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

// Template for the index page
const indexTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>BPF Process Monitor</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://unpkg.com/react@17/umd/react.development.js"></script>
    <script src="https://unpkg.com/react-dom@17/umd/react-dom.development.js"></script>
    <script src="https://unpkg.com/babel-standalone@6/babel.min.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body>
    <div id="root"></div>
    <script type="text/babel" src="/app.jsx"></script>
</body>
</html>`
