package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ProcessInfo holds detailed information about a process
type ProcessInfo struct {
	PID           uint32
	PPID          uint32
	Comm          string
	CmdLine       string
	ExePath       string
	UID           uint32
	Username      string
	ParentComm    string
	ParentExePath string
	WorkingDir    string
	Environment   []string
	ContainerID   string // Container ID if process is containerized
}

// GetProcessInfo gathers detailed information about a process from /proc
func GetProcessInfo(pid uint32, ppid uint32) (*ProcessInfo, error) {
	info := &ProcessInfo{
		PID:  pid,
		PPID: ppid,
	}

	// Get process name
	if exepath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		info.ExePath = exepath
		info.Comm = filepath.Base(exepath)
	} else {
		fmt.Printf("couldn't look up exepath err %v\n", err)
	}

	// Get command line
	if cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		info.CmdLine = string(cmdline)
	}

	// Get working directory
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		info.WorkingDir = cwd
	}

	// Get parent process name and path if possible
	if ppid > 0 {
		if parentexepath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid)); err == nil {
			info.ParentExePath = parentexepath
			info.ParentComm = filepath.Base(parentexepath)
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

	// Get environment
	if env, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
		info.Environment = strings.Split(string(env), "\x00")
	}

	return info, nil
}

type MetadataRequest struct {
	done chan *ProcessInfo // Channel for this specific process
	pid  uint32
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
func (mc *MetadataCollector) CollectProcessInfo(pid uint32, ppid uint32) <-chan *ProcessInfo {
	done := make(chan *ProcessInfo, 1) // Buffer of 1 for this specific process

	go func() {
		info, err := GetProcessInfo(pid, ppid)
		if err != nil {
			info = &ProcessInfo{
				PID:  pid,
				PPID: ppid,
				Comm: fmt.Sprintf("unknown-%d", pid),
			}
		}
		mc.mu.Lock()
		mc.processes[pid] = info
		mc.mu.Unlock()

		done <- info
		close(done) // Signal we're done with this collection
	}()

	return done
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
