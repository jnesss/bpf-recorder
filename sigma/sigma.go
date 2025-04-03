package sigma 

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/fsnotify/fsnotify"
)

// Detector manages Sigma rules and detection
type Detector struct {
	RulesDir   string
	db         *sql.DB
	evaluators map[string]*evaluator.RuleEvaluator
	running    bool
	eventTypes []string
	reloadChan chan bool         // Channel to signal rule reloading
	watcher    *fsnotify.Watcher // File system watcher
}

// SigmaMatch represents a process that matched a Sigma rule
type SigmaMatch struct {
	ID                int64     `json:"id"`
	EventID           int64     `json:"event_id"`
	EventType         string    `json:"event_type"`
	RuleID            string    `json:"rule_id"`
	RuleName          string    `json:"rule_name"`
	ProcessID         int64     `json:"process_id"`
	ProcessName       string    `json:"process_name"`
	CommandLine       string    `json:"command_line"`
	ParentProcessName string    `json:"parent_process_name"`
	ParentCommandLine string    `json:"parent_command_line"`
	Username          string    `json:"username"`
	Timestamp         time.Time `json:"timestamp"`
	Severity          string    `json:"severity"`
	Status            string    `json:"status"`
	MatchDetails      []string  `json:"match_details"`
	EventData         string    `json:"event_data"`
	CreatedAt         time.Time `json:"created_at"`
}

// MatchResult represents the result of a rule evaluation
type MatchResult struct {
	Match        bool
	Rule         sigma.Rule
	MatchDetails []string
}

// Helper function to create hardcoded config
func createHardcodedConfig() sigma.Config {
	return sigma.Config{
		Title: "BPF Recorder Config",
		FieldMappings: map[string]sigma.FieldMapping{
			"CommandLine":       {TargetNames: []string{"CommandLine"}},
			"ParentCommandLine": {TargetNames: []string{"ParentCommandLine"}},
			"Image":             {TargetNames: []string{"Image"}},
			"ParentImage":       {TargetNames: []string{"ParentImage"}},
			"User":              {TargetNames: []string{"Username"}},
			"ProcessId":         {TargetNames: []string{"ProcessId"}},
			"ParentProcessId":   {TargetNames: []string{"ParentProcessId"}},
		},
	}
}

// NewSigmaDetector creates a new Sigma detector
func NewDetector(rulesDir string, db *sql.DB) (*Detector, error) {
	// Create watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %v", err)
	}

	detector := &Detector{
		RulesDir:   rulesDir,
		db:         db,
		evaluators: make(map[string]*evaluator.RuleEvaluator),
		running:    false,
		eventTypes: []string{"process"},
		reloadChan: make(chan bool, 1), // Buffer of 1 to prevent blocking
		watcher:    watcher,
	}

	// Create enabled_rules and disabled_rules directories if they don't exist
	enabledDir := filepath.Join(rulesDir, "enabled_rules")
	disabledDir := filepath.Join(rulesDir, "disabled_rules")

	for _, dir := range []string{enabledDir, disabledDir} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				watcher.Close() // Close watcher on error
				return nil, fmt.Errorf("failed to create directory %s: %v", dir, err)
			}
		}
	}

	// Start watching directories
	if err := detector.setupWatcher(); err != nil {
		watcher.Close() // Close watcher on error
		return nil, fmt.Errorf("failed to set up file watcher: %v", err)
	}

	// Load rules from enabled_rules directory
	if err := detector.LoadRules(); err != nil {
		return nil, fmt.Errorf("failed to load rules: %v", err)
	}

	return detector, nil
}

// Add a new method to set up the file watcher
func (sd *Detector) setupWatcher() error {
	// watch the enabled directory (changes dont matter in disabled_rules dir)
	enabledDir := filepath.Join(sd.RulesDir, "enabled_rules")

	if err := sd.watcher.Add(enabledDir); err != nil {
		return fmt.Errorf("failed to watch directory %s: %v", enabledDir, err)
	}
	fmt.Printf("Watching directory for changes: %s\n", enabledDir)

	// Start the goroutine that watches for file changes
	go sd.watchFileChanges()

	return nil
}

// Add a method to handle file change events
func (sd *Detector) watchFileChanges() {
	for {
		select {
		case event, ok := <-sd.watcher.Events:
			if !ok {
				return // Channel closed
			}

			// We only care about rule files
			if !strings.HasSuffix(event.Name, ".yml") && !strings.HasSuffix(event.Name, ".yaml") {
				continue
			}

			// Log the event
			fmt.Printf("File system event: %s, %s\n", event.Name, event.Op.String())

			// For any write, create or remove operation, trigger a reload
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
				fmt.Printf("Detected rule change: %s\n", event.Name)
				sd.ReloadRules()
			}

		case err, ok := <-sd.watcher.Errors:
			if !ok {
				return // Channel closed
			}
			fmt.Printf("File watcher error: %v\n", err)
		}
	}
}

// Add a new method to load rules with the hardcoded config
func (sd *Detector) LoadRulesWithConfig(rulesDir string, config sigma.Config) error {
	// Clear existing evaluators
	sd.evaluators = make(map[string]*evaluator.RuleEvaluator)

	// Get all files in the rules directory
	files, err := ioutil.ReadDir(rulesDir)
	if err != nil {
		return err
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() && (filepath.Ext(file.Name()) == ".yml" || filepath.Ext(file.Name()) == ".yaml") {
			filePath := filepath.Join(rulesDir, file.Name())

			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Warning: Failed to read rule file %s: %v\n", filePath, err)
				continue
			}

			// Check if this is actually a rule file
			fileType := sigma.InferFileType(content)
			if fileType != sigma.RuleFile {
				fmt.Printf("File is not a Sigma rule: %s\n", filePath)
				continue
			}

			rule, err := sigma.ParseRule(content)
			if err != nil {
				fmt.Printf("Warning: Failed to parse rule file %s: %v\n", filePath, err)
				continue
			}

			// Create evaluator with the hardcoded config
			ruleEvaluator := evaluator.ForRule(rule,
				evaluator.WithConfig(config),
				evaluator.WithPlaceholderExpander(func(ctx context.Context, placeholderName string) ([]string, error) {
					return nil, nil
				}),
				evaluator.CountImplementation(func(ctx context.Context, key evaluator.GroupedByValues) (float64, error) {
					return 0, nil
				}),
				evaluator.SumImplementation(func(ctx context.Context, key evaluator.GroupedByValues, value float64) (float64, error) {
					return 0, nil
				}),
				evaluator.AverageImplementation(func(ctx context.Context, key evaluator.GroupedByValues, value float64) (float64, error) {
					return 0, nil
				}))

			sd.evaluators[rule.ID] = ruleEvaluator
			fmt.Printf("Loaded rule: %s (%s)\n", rule.Title, rule.ID)
			count++
		}
	}

	fmt.Printf("Loaded %d Sigma rules from %s\n", count, rulesDir)
	return nil
}

// LoadRules loads all Sigma rules from the rules directory
// Modify your LoadRules function to load from enabled_rules
func (sd *Detector) LoadRules() error {
	// Clear existing evaluators
	sd.evaluators = make(map[string]*evaluator.RuleEvaluator)

	// Get path to enabled rules directory
	enabledDir := filepath.Join(sd.RulesDir, "enabled_rules")

	// Create directory if it doesn't exist
	if _, err := os.Stat(enabledDir); os.IsNotExist(err) {
		if err := os.MkdirAll(enabledDir, 0755); err != nil {
			return fmt.Errorf("failed to create enabled_rules directory: %v", err)
		}
	}

	// Get all files in the enabled rules directory
	files, err := ioutil.ReadDir(enabledDir)
	if err != nil {
		return err
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() && (filepath.Ext(file.Name()) == ".yml" || filepath.Ext(file.Name()) == ".yaml") {
			filePath := filepath.Join(enabledDir, file.Name())
			if err := sd.LoadRuleFile(filePath); err != nil {
				fmt.Printf("Warning: Failed to load rule file %s: %v\n", filePath, err)
				continue
			}
			count++
		}
	}

	fmt.Printf("Loaded %d Sigma rules from %s\n", count, enabledDir)
	return nil
}

func (sd *Detector) ReloadRules() {
	select {
	case sd.reloadChan <- true:
		// Signal sent successfully
	default:
		// Channel already has a reload signal pending
	}
}

// LoadRuleFile loads a single rule file
func (sd *Detector) LoadRuleFile(filePath string) error {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Check if this is actually a rule file
	fileType := sigma.InferFileType(content)
	if fileType != sigma.RuleFile {
		return fmt.Errorf("file is not a Sigma rule: %s", filePath)
	}

	rule, err := sigma.ParseRule(content)
	if err != nil {
		return err
	}

	// Prepare evaluator options
	options := []evaluator.Option{
		// Add our hardcoded config
		evaluator.WithConfig(createHardcodedConfig()),
		evaluator.WithPlaceholderExpander(func(ctx context.Context, placeholderName string) ([]string, error) {
			// Implement placeholder expansion if needed
			return nil, nil
		}),
		evaluator.CountImplementation(func(ctx context.Context, key evaluator.GroupedByValues) (float64, error) {
			// Implement count aggregation if needed
			return 0, nil
		}),
		evaluator.SumImplementation(func(ctx context.Context, key evaluator.GroupedByValues, value float64) (float64, error) {
			// Implement sum aggregation if needed
			return 0, nil
		}),
		evaluator.AverageImplementation(func(ctx context.Context, key evaluator.GroupedByValues, value float64) (float64, error) {
			// Implement average aggregation if needed
			return 0, nil
		}),
	}

	// Create evaluator with necessary implementations
	ruleEvaluator := evaluator.ForRule(rule, options...)

	sd.evaluators[rule.ID] = ruleEvaluator
	log.Printf("Loaded rule: %s (%s)", rule.Title, rule.ID)
	return nil
}

// GetLastProcessedID gets the last processed ID for an event type
func (sd *Detector) GetLastProcessedID(eventType string) (int64, error) {
	query := `SELECT last_id FROM detector_state WHERE event_type = ? LIMIT 1`

	var lastID int64
	err := sd.db.QueryRow(query, eventType).Scan(&lastID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Initialize this event type
			initQuery := `
			INSERT INTO detector_state 
				(event_type, last_id, last_processed_time, updated_at) 
			VALUES 
				(?, 0, datetime('now'), datetime('now'))`

			_, err = sd.db.Exec(initQuery, eventType)
			if err != nil {
				return 0, fmt.Errorf("failed to initialize state for event type %s: %v", eventType, err)
			}
			return 0, nil
		}
		return 0, err
	}

	return lastID, nil
}

// UpdateDetectorState updates the state for an event type
func (sd *Detector) UpdateDetectorState(eventType string, lastID int64, matchCount int) error {
	query := `
	UPDATE detector_state SET 
		last_id = ?,
		last_processed_time = datetime('now'),
		match_count = match_count + ?,
		updated_at = datetime('now')
	WHERE event_type = ?`

	_, err := sd.db.Exec(query, lastID, matchCount, eventType)
	return err
}

// CheckEvent checks if an event matches any Sigma rules and returns detailed match results
func (sd *Detector) CheckEvent(ctx context.Context, event map[string]interface{}, eventType string) []MatchResult {
	var results []MatchResult

	for _, ruleEvaluator := range sd.evaluators {
		// Use the Matches method to evaluate the event
		result, err := ruleEvaluator.Matches(ctx, event)
		if err != nil {
			log.Printf("Error evaluating message of type [%s], err %v", eventType, err)
			continue
		}

		if result.Match {
			var matchConditions []string
			for k, v := range result.SearchResults {
				if v {
					matchConditions = append(matchConditions, k)
				}
			}

			// Create a match result with details
			matchResult := MatchResult{
				Match: true,
				Rule:  ruleEvaluator.Rule, // Access as field, not function
				MatchDetails: []string{
					fmt.Sprintf("Matched conditions: %s", strings.Join(matchConditions, ", ")),
				},
			}

			results = append(results, matchResult)
			log.Printf("Event matched rule %s with conditions %s", ruleEvaluator.Rule.ID, strings.Join(matchConditions, ", "))
		}
	}

	return results
}

// StoreMatch stores a rule match in the database
func (sd *Detector) StoreMatch(match MatchResult, event map[string]interface{}, eventType string) error {
	// Convert event data to JSON
	eventDataJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %v", err)
	}

	// Extract process info
	var processID int64
	var processName, commandLine, parentProcessName, parentCommandLine, username string

	// Extract event ID
	eventID, ok := event["id"].(int64)
	if !ok {
		if id, ok := event["id"].(int); ok {
			eventID = int64(id)
		} else {
			return fmt.Errorf("event has no valid ID")
		}
	}

	// Extract other fields with type assertion
	if id, ok := event["ProcessId"].(int64); ok {
		processID = id
	} else if id, ok := event["ProcessId"].(int); ok {
		processID = int64(id)
	}

	if name, ok := event["Image"].(string); ok {
		processName = name
	}

	if cmd, ok := event["CommandLine"].(string); ok {
		commandLine = cmd
	}

	if name, ok := event["ParentImage"].(string); ok {
		parentProcessName = name
	}

	if cmd, ok := event["ParentCommandLine"].(string); ok {
		parentCommandLine = cmd
	}

	if user, ok := event["Username"].(string); ok {
		username = user
	} else if user, ok := event["User"].(string); ok {
		username = user
	}

	// Prepare match details
	matchDetailsJSON, _ := json.Marshal(match.MatchDetails)

	// Prepare severity
	severity := match.Rule.Level
	if severity == "" {
		severity = "medium"
	}

	// Insert the match
	query := `
	INSERT INTO sigma_matches (
		event_id,
		event_type,
		rule_id,
		rule_name,
		process_id,
		process_name,
		command_line,
		parent_process_name,
		parent_command_line,
		username,
		timestamp,
		severity,
		status,
		match_details,
		event_data,
		created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, 'new', ?, ?, datetime('now'))`

	_, err = sd.db.Exec(
		query,
		eventID,
		eventType,
		match.Rule.ID,
		match.Rule.Title,
		processID,
		processName,
		commandLine,
		parentProcessName,
		parentCommandLine,
		username,
		severity,
		string(matchDetailsJSON),
		string(eventDataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to insert match: %v", err)
	}

	log.Printf("Stored match for rule %s: %s", match.Rule.ID, match.Rule.Title)
	return nil
}

// StartPolling starts polling for all event types
func (sd *Detector) StartPolling(ctx context.Context, interval time.Duration) error {
    if sd.running {
        return fmt.Errorf("detector is already running")
    }

    sd.running = true

    // Create WaitGroup to track goroutines
    var wg sync.WaitGroup

    // Start rule reloader goroutine
    wg.Add(1)
    go func() {
        defer wg.Done()
        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-ctx.Done():
                return
            case <-sd.reloadChan:
                fmt.Println("Reloading Sigma rules...")
                if err := sd.LoadRules(); err != nil {
                    fmt.Printf("Error reloading rules: %v\n", err)
                }
            case <-ticker.C:
                // Check periodically
            }
        }
    }()

    // Start event type pollers
    for _, eventType := range sd.eventTypes {
        eventType := eventType // Create new variable for goroutine closure
        wg.Add(1)

        go func() {
            defer wg.Done()
            ticker := time.NewTicker(interval)
            defer ticker.Stop()

            for {
                select {
                case <-ctx.Done():
                    log.Printf("Stopping %s event polling...", eventType)
                    return
                case <-ticker.C:
                    // Get the last processed ID for this event type
                    lastID, err := sd.GetLastProcessedID(eventType)
                    if err != nil {
                        log.Printf("Error retrieving last processed ID for %s: %v", eventType, err)
                        continue
                    }

                    // Fetch new events
                    events, err := sd.FetchNewEvents(eventType, lastID)
                    if err != nil {
                        log.Printf("Error fetching %s events: %v", eventType, err)
                        continue
                    }

                    // Process events if we have any and context isn't cancelled
                    if len(events) > 0 {
                        log.Printf("Processing %d new %s events", len(events), eventType)

                        var newLastID int64
                        var matchCount int

                        // Check events against rules
                        for _, event := range events {
                            // Check context before processing each event
                            if ctx.Err() != nil {
                                return
                            }

                            id := event["id"].(int64)
                            if id > newLastID {
                                newLastID = id
                            }

                            // Check against all rules with detailed results
                            matches := sd.CheckEvent(ctx, event, eventType)

                            // Store matches
                            for _, match := range matches {
                                if err := sd.StoreMatch(match, event, eventType); err != nil {
                                    log.Printf("Error storing match: %v", err)
                                }
                                matchCount++
                            }
                        }

                        // Update state if we haven't been cancelled
                        if ctx.Err() == nil && newLastID > lastID {
                            if err := sd.UpdateDetectorState(eventType, newLastID, matchCount); err != nil {
                                log.Printf("Error updating state for %s: %v", eventType, err)
                            }
                        }
                    }
                }
            }
        }()

        log.Printf("Started polling for %s events", eventType)
    }

    // Create done channel for cleanup
    done := make(chan struct{})
    go func() {
        wg.Wait()
        close(done)
    }()

    // Wait for either context cancellation or completion
    select {
    case <-ctx.Done():
        log.Println("Sigma detection stopping...")
        // Wait for goroutines with timeout
        select {
        case <-done:
            log.Println("Sigma detection stopped gracefully")
        case <-time.After(5 * time.Second):
            log.Println("Warning: Some Sigma detection goroutines didn't stop in time")
        }
    case <-done:
        log.Println("Sigma detection stopped")
    }

    sd.running = false
    return nil
}

// StopPolling stops the polling
func (sd *Detector) StopPolling() {
	sd.running = false
	if sd.watcher != nil {
		sd.watcher.Close() // Close the watcher
	}

	log.Println("Sigma detection polling stopped")
}

// FetchNewEvents fetches new events of a specific type
func (sd *Detector) FetchNewEvents(eventType string, lastID int64) ([]map[string]interface{}, error) {
	var query string

	switch eventType {
	case "process":
		query = `
		SELECT 
			p.id, 
			p.exe_path as Image, 
			p.cmdline as CommandLine, 
			pp.comm as ParentImage, 
			pp.exe_path as ParentCommandLine, 
			p.username as User, 
			p.username as Username, 
			p.working_dir as CurrentDirectory, 
			p.pid as ProcessId, 
			pp.pid as ParentProcessId, 
			p.uid as UID, 
			p.gid as GID 
		FROM processes p
		LEFT JOIN processes pp ON p.ppid = pp.pid AND pp.id < p.id
		WHERE p.id > ?
		ORDER BY p.id ASC
		LIMIT 1000`
	default:
		return nil, fmt.Errorf("unknown event type: %s", eventType)
	}

	// Execute the query
	rows, err := sd.db.Query(query, lastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []map[string]interface{}

	// Process each row and convert to map for Sigma evaluation
	for rows.Next() {
		var (
			id                int64
			image             sql.NullString
			commandLine       sql.NullString
			parentImage       sql.NullString
			parentCommandLine sql.NullString
			user              sql.NullString
			username          sql.NullString
			currentDirectory  sql.NullString
			processId         sql.NullInt64
			parentProcessId   sql.NullInt64
			uid               sql.NullString
			gid               sql.NullString
		)

		err := rows.Scan(
			&id,
			&image,
			&commandLine,
			&parentImage,
			&parentCommandLine,
			&user,
			&username,
			&currentDirectory,
			&processId,
			&parentProcessId,
			&uid,
			&gid,
		)
		if err != nil {
			return nil, err
		}

		// Create map for Sigma evaluation
		event := map[string]interface{}{
			"id": id,
		}

		// Add fields if they are not NULL
		if image.Valid {
			event["Image"] = image.String
		}

		if commandLine.Valid {
			event["CommandLine"] = commandLine.String
		}

		if parentImage.Valid {
			event["ParentImage"] = parentImage.String
		}

		if parentCommandLine.Valid {
			event["ParentCommandLine"] = parentCommandLine.String
		}

		if user.Valid {
			event["User"] = user.String
		}

		if username.Valid {
			event["Username"] = username.String
		}

		if currentDirectory.Valid {
			event["CurrentDirectory"] = currentDirectory.String
		}

		if processId.Valid {
			event["ProcessId"] = processId.Int64
		}

		if parentProcessId.Valid {
			event["ParentProcessId"] = parentProcessId.Int64
		}

		if uid.Valid {
			event["UID"] = uid.String
		}

		if gid.Valid {
			event["GID"] = gid.String
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

// GetMatches retrieves sigma matches from the database with filters
func (sd *Detector) GetMatches(limit int, offset int, filters map[string]string) ([]SigmaMatch, error) {
	query := `
    SELECT 
        id, event_id, event_type, rule_id, rule_name, 
        process_id, process_name, command_line,
        parent_process_name, parent_command_line, username,
        timestamp, severity, status, match_details, event_data, created_at
    FROM sigma_matches`

	whereClause := []string{}
	args := []interface{}{}

	// Add filters to WHERE clause
	if status, ok := filters["status"]; ok && status != "" && status != "all" {
		whereClause = append(whereClause, "status = ?")
		args = append(args, status)
	}

	if severity, ok := filters["severity"]; ok && severity != "" && severity != "all" {
		whereClause = append(whereClause, "severity = ?")
		args = append(args, severity)
	}

	if ruleID, ok := filters["rule"]; ok && ruleID != "" && ruleID != "all" {
		whereClause = append(whereClause, "rule_id = ?")
		args = append(args, ruleID)
	}

	// Add WHERE clause if we have any conditions
	if len(whereClause) > 0 {
		query += " WHERE " + strings.Join(whereClause, " AND ")
	}

	// Add ordering and pagination
	query += ` ORDER BY timestamp DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	// Execute query
	rows, err := sd.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []SigmaMatch

	for rows.Next() {
		var match SigmaMatch
		var matchDetailsJSON, eventDataJSON string

		err := rows.Scan(
			&match.ID, &match.EventID, &match.EventType, &match.RuleID, &match.RuleName,
			&match.ProcessID, &match.ProcessName, &match.CommandLine,
			&match.ParentProcessName, &match.ParentCommandLine, &match.Username,
			&match.Timestamp, &match.Severity, &match.Status, &matchDetailsJSON, &eventDataJSON, &match.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON fields
		json.Unmarshal([]byte(matchDetailsJSON), &match.MatchDetails)
		match.EventData = eventDataJSON

		matches = append(matches, match)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return matches, nil
}

// GetMatchStats retrieves statistics about sigma matches
func (sd *Detector) GetMatchStats() (map[string]interface{}, error) {
	// Get total rules count
	var totalRules int
	err := sd.db.QueryRow("SELECT COUNT(*) FROM (SELECT DISTINCT rule_id FROM sigma_matches)").Scan(&totalRules)
	if err != nil {
		return nil, err
	}

	// Get count by severity
	sevCounts := make(map[string]int)
	rows, err := sd.db.Query("SELECT severity, COUNT(*) FROM sigma_matches GROUP BY severity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		sevCounts[severity] = count
	}

	// Get count by status
	statusCounts := make(map[string]int)
	rows, err = sd.db.Query("SELECT status, COUNT(*) FROM sigma_matches GROUP BY status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		statusCounts[status] = count
	}

	// Get recent alerts (last 24h)
	var last24h int
	yesterday := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	err = sd.db.QueryRow("SELECT COUNT(*) FROM sigma_matches WHERE timestamp > ?", yesterday).Scan(&last24h)
	if err != nil {
		return nil, err
	}

	// Get recent alerts (last 7d)
	var last7d int
	lastWeek := time.Now().Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	err = sd.db.QueryRow("SELECT COUNT(*) FROM sigma_matches WHERE timestamp > ?", lastWeek).Scan(&last7d)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"totalRules":     totalRules,
		"activeRules":    len(sd.evaluators),
		"alertsLast24h":  last24h,
		"alertsLast7d":   last7d,
		"severityCounts": sevCounts,
		"statusCounts":   statusCounts,
	}, nil
}

// UpdateMatchStatus updates the status of a match
func (sd *Detector) UpdateMatchStatus(matchID int64, newStatus string) error {
	// Validate status
	validStatuses := map[string]bool{
		"new":            true,
		"in_progress":    true,
		"resolved":       true,
		"false_positive": true,
	}

	if !validStatuses[newStatus] {
		return fmt.Errorf("invalid status: %s", newStatus)
	}

	// Update status
	_, err := sd.db.Exec(
		"UPDATE sigma_matches SET status = ? WHERE id = ?",
		newStatus, matchID,
	)

	return err
}

