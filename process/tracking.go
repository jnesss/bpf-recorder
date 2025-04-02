package process

import (
    "bytes"
    "fmt"
    "os"
    "os/user"
    "regexp"
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

    // Get working directory
    if cwd, err := os.Readlink(fmt.Sprintf("%s/cwd", procDir)); err == nil {
        info.WorkingDir = cwd
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
