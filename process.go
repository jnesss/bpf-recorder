package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
)

// ProcessInfo holds detailed information about a process
type ProcessInfo struct {
	PID         uint32
	PPID        uint32
	Comm        string
	CmdLine     []string
	ExePath     string
	UID         uint32
	Username    string
	ParentComm  string
	WorkingDir  string
	Environment []string
	ContainerID string // Container ID if process is containerized
}

// GetProcessInfo gathers detailed information about a process from /proc
func GetProcessInfo(pid uint32) (*ProcessInfo, error) {
	info := &ProcessInfo{
		PID: pid,
	}

	// Get process status info (includes PPID, UID)
	status, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err == nil {
		lines := strings.Split(string(status), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			switch parts[0] {
			case "PPid:":
				ppid, _ := strconv.ParseUint(parts[1], 10, 32)
				info.PPID = uint32(ppid)
			case "Uid:":
				uid, _ := strconv.ParseUint(parts[1], 10, 32)
				info.UID = uint32(uid)
				if u, err := user.LookupId(parts[1]); err == nil {
					info.Username = u.Username
				}
			}
		}
	}

	// Get command line
	if cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if len(args) > 0 {
			info.CmdLine = args
		}
	}

	// Get executable path
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		info.ExePath = exe
	}

	// Get working directory
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		info.WorkingDir = cwd
	}

	// Get environment
	if env, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
		info.Environment = strings.Split(string(env), "\x00")
	}

	// Get parent process name if possible
	if info.PPID > 0 {
		if comm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", info.PPID)); err == nil {
			info.ParentComm = strings.TrimSpace(string(comm))
		}
	}

	// Check if process is in a container by examining cgroup info
	if cgroupData, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		lines := strings.Split(string(cgroupData), "\n")
		for _, line := range lines {
			// Look for docker/containerd ID in cgroup path
			if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
				parts := strings.Split(line, "/")
				for i := len(parts) - 1; i >= 0; i-- {
					// Look for container ID format (64 hex chars for full ID, 12 for short ID)
					part := parts[i]
					if len(part) >= 12 && len(part) <= 64 {
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

	return info, nil
}

// MetadataCollector handles asynchronous collection of process metadata
type MetadataCollector struct {
	processes map[uint32]*ProcessInfo
	mu        sync.RWMutex
}

// NewMetadataCollector creates a new metadata collector
func NewMetadataCollector() *MetadataCollector {
	return &MetadataCollector{
		processes: make(map[uint32]*ProcessInfo),
	}
}

// CollectProcessInfo asynchronously collects process information
func (mc *MetadataCollector) CollectProcessInfo(pid uint32) {
	go func() {
		info, err := GetProcessInfo(pid)
		if err != nil {
			return
		}

		mc.mu.Lock()
		mc.processes[pid] = info
		mc.mu.Unlock()
	}()
}

// GetProcessInfo retrieves collected process information
func (mc *MetadataCollector) GetProcessInfo(pid uint32) *ProcessInfo {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.processes[pid]
}

// RemoveProcess removes a process from the collector
func (mc *MetadataCollector) RemoveProcess(pid uint32) {
	mc.mu.Lock()
	delete(mc.processes, pid)
	mc.mu.Unlock()
}
