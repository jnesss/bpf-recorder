package process

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ProcessMap is a thread-safe map of process information
type ProcessMap struct {
	processes map[uint32]*ProcessInfo
	mu        sync.RWMutex
}

// NewProcessMap creates a new process map
func NewProcessMap() *ProcessMap {
	return &ProcessMap{
		processes: make(map[uint32]*ProcessInfo),
	}
}

// Add adds or updates a process in the map
func (pm *ProcessMap) Add(pid uint32, info *ProcessInfo) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.processes[pid] = info
}

// Get retrieves process info from the map
func (pm *ProcessMap) Get(pid uint32) (*ProcessInfo, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	info, exists := pm.processes[pid]
	return info, exists
}

// Remove removes a process from the map
func (pm *ProcessMap) Remove(pid uint32) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.processes, pid)
}

// List returns all processes in the map
func (pm *ProcessMap) List() []*ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	processes := make([]*ProcessInfo, 0, len(pm.processes))
	for _, p := range pm.processes {
		processes = append(processes, p)
	}
	return processes
}

// Simple cache for username lookups
var (
	usernameCacheMutex sync.RWMutex
	usernameCache      = make(map[uint32]string)
)

// Cache container ID regex
var containerIDRegex = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

func GetUsernameFromUID(uid uint32) string {
	// Check cache first
	usernameCacheMutex.RLock()
	if username, ok := usernameCache[uid]; ok {
		usernameCacheMutex.RUnlock()
		return username
	}
	usernameCacheMutex.RUnlock()

	// Not in cache, look it up
	if u, err := user.LookupId(fmt.Sprintf("%d", uid)); err == nil {
		usernameCacheMutex.Lock()
		usernameCache[uid] = u.Username
		usernameCacheMutex.Unlock()
		return u.Username
	}
	return ""
}

// CollectProcMetadata gathers information about a process from /proc
func CollectProcMetadata(pid uint32, info *ProcessInfo) bool {
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Check if process still exists
	if _, err := os.Stat(procDir); os.IsNotExist(err) {
		return false // Process already gone
	}

	// Get executable path
	if exePath, err := os.Readlink(fmt.Sprintf("%s/exe", procDir)); err == nil {
		info.ExePath = exePath
	}

	// Get command line with proper null-byte handling
	if cmdlineBytes, err := os.ReadFile(fmt.Sprintf("%s/cmdline", procDir)); err == nil && len(cmdlineBytes) > 0 {
		// Handle the null-byte separated arguments
		args := bytes.Split(cmdlineBytes, []byte{0})
		var cmdArgs []string
		for _, arg := range args {
			if len(arg) > 0 {
				cmdArgs = append(cmdArgs, string(arg))
			}
		}
		if len(cmdArgs) > 0 {
			info.CmdLine = strings.Join(cmdArgs, " ")
		}
	}

	// Get initial working directory
	if cwd, err := os.Readlink(fmt.Sprintf("%s/cwd", procDir)); err == nil {
		info.WorkingDir = cwd
	}

	// Get environment variables - typically static for process lifetime
	if env, err := getProcessEnvironment(pid); err == nil {
		info.Environment = env
	}

	// Get username from UID if needed
	if info.UID > 0 && info.Username == "" {
		if u, err := user.LookupId(fmt.Sprintf("%d", info.UID)); err == nil {
			info.Username = u.Username
		}
	}

	// Check for container ID if not already detected
	if info.ContainerID == "" {
		if cgroupData, err := os.ReadFile(fmt.Sprintf("%s/cgroup", procDir)); err == nil {
			lines := strings.Split(string(cgroupData), "\n")
			for _, line := range lines {
				if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
					parts := strings.Split(line, "/")
					for i := len(parts) - 1; i >= 0; i-- {
						part := parts[i]
						if containerIDRegex.MatchString(part) {
							info.ContainerID = part
							break
						}
					}
					if info.ContainerID != "" {
						break
					}
				}
			}
		}
	}

	return true // Successfully read proc data
}

// FormatProcessEvent formats a process event for logging
func FormatProcessEvent(info *ProcessInfo, eventType uint32) string {
	var eventTypeStr string

	switch eventType {
	case 1: // EVENT_PROCESS_EXEC
		eventTypeStr = "EXEC"
	case 2: // EVENT_PROCESS_EXIT
		eventTypeStr = "EXIT"
	default:
		eventTypeStr = "UNKNOWN"
	}

	// Basic format for all process events
	basic := fmt.Sprintf("%s: pid=%d comm=%s", eventTypeStr, info.PID, info.Comm)

	// Add details based on event type
	if eventType == 1 { // EVENT_PROCESS_EXEC
		details := fmt.Sprintf("ppid=%d uid=%d", info.PPID, info.UID)

		if info.Username != "" {
			details += fmt.Sprintf(" user=%s", info.Username)
		}

		if info.ExePath != "" {
			details += fmt.Sprintf(" path=%s", info.ExePath)
		}

		if info.CmdLine != "" {
			details += fmt.Sprintf(" cmdline=%s", info.CmdLine)
		}

		if info.ContainerID != "" {
			details += fmt.Sprintf(" container=%s", info.ContainerID)
		}

		return fmt.Sprintf("%s %s", basic, details)
	} else if eventType == 2 { // EVENT_PROCESS_EXIT
		duration := "unknown"
		if !info.StartTime.IsZero() {
			duration = info.ExitTime.Sub(info.StartTime).String()
		}

		return fmt.Sprintf("%s exit_code=%d runtime=%s", basic, info.ExitCode, duration)
	}

	return basic
}

// readProcFile reads a file from /proc and returns its contents
func readProcFile(pid uint32, filename string) (string, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, filename))
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(data)), nil
}

// getProcessEnvironment reads and parses environment variables
func getProcessEnvironment(pid uint32) ([]string, error) {
	data, err := readProcFile(pid, "environ")
	if err != nil {
		return nil, err
	}

	// Split on null bytes
	return strings.Split(data, "\x00"), nil
}

// getFileDescriptors gets count and list of open files
func getFileDescriptors(pid uint32) (int, []string, error) {
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := ioutil.ReadDir(fdPath)
	if err != nil {
		return 0, nil, err
	}

	var openFiles []string
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
		if err == nil {
			openFiles = append(openFiles, link)
		}
	}

	return len(fds), openFiles, nil
}

// getMemoryUsage gets memory usage statistics
func getMemoryUsage(pid uint32) (uint64, float64, error) {
	// Read /proc/[pid]/statm for memory info
	data, err := readProcFile(pid, "statm")
	if err != nil {
		return 0, 0.0, err
	}

	fields := strings.Fields(data)
	if len(fields) < 2 {
		return 0, 0.0, fmt.Errorf("invalid statm format")
	}

	// First field is total program size in pages
	// Second field is resident set size in pages
	rss, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0.0, err
	}

	// Convert pages to bytes (multiply by page size, typically 4KB)
	memoryBytes := rss * 4096

	// Get total system memory for percentage calculation
	sysInfo, err := readProcFile(pid, "../meminfo")
	if err != nil {
		return memoryBytes, 0.0, nil
	}

	var totalMem uint64
	for _, line := range strings.Split(sysInfo, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					totalMem = totalKB * 1024
					break
				}
			}
		}
	}

	var memoryPercent float64
	if totalMem > 0 {
		memoryPercent = float64(memoryBytes) / float64(totalMem) * 100
	}

	return memoryBytes, memoryPercent, nil
}

// getCPUUsage calculates CPU usage percentage
func getCPUUsage(pid uint32) (float64, error) {
	// Read /proc/[pid]/stat for CPU info
	data, err := readProcFile(pid, "stat")
	if err != nil {
		return 0.0, err
	}

	fields := strings.Fields(data)
	if len(fields) < 15 {
		return 0.0, fmt.Errorf("invalid stat format")
	}

	// Fields 14 and 15 are utime and stime (user and system CPU time)
	utime, err := strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return 0.0, err
	}

	stime, err := strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return 0.0, err
	}

	// Total CPU time in jiffies
	totalTime := utime + stime

	// Get uptime from /proc/uptime
	uptime, err := readProcFile(pid, "../uptime")
	if err != nil {
		return 0.0, err
	}

	uptimeSeconds, err := strconv.ParseFloat(strings.Fields(uptime)[0], 64)
	if err != nil {
		return 0.0, err
	}

	// Calculate CPU usage percentage
	cpuUsage := 100 * (float64(totalTime) / 100) / uptimeSeconds

	return cpuUsage, nil
}

// getThreadCount gets the number of threads
func getThreadCount(pid uint32) (int, error) {
	// Read /proc/[pid]/status for thread count
	data, err := readProcFile(pid, "status")
	if err != nil {
		return 0, err
	}

	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "Threads:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}

	return 0, fmt.Errorf("thread count not found")
}
