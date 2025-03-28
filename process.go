package main

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
)

// Event types
const (
	EventExec = 1
	EventExit = 2
)

// Event represents a process event
type Event struct {
	PID       uint32
	Pad0      uint32
	Timestamp uint64
	Comm      [16]byte
	Filename  [64]byte
	EventType int32
	ExitCode  int32
}

// Process tree map
var (
	processTree = make(map[uint32]string)
	processMu   sync.RWMutex
)

// GetParentPID retrieves parent PID from /proc
func GetParentPID(pid uint32) uint32 {
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	content, err := ioutil.ReadFile(statusFile)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ppid, err := strconv.ParseUint(parts[1], 10, 32)
				if err == nil {
					return uint32(ppid)
				}
			}
			break
		}
	}

	return 0
}

// GetCommandLineArgs retrieves command line from /proc
func GetCommandLineArgs(pid uint32) []string {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	content, err := ioutil.ReadFile(cmdlinePath)
	if err != nil {
		return nil
	}

	if len(content) == 0 {
		return nil
	}

	// Replace null bytes with spaces except the last one
	for i := 0; i < len(content)-1; i++ {
		if content[i] == 0 {
			content[i] = ' '
		}
	}

	return []string{strings.TrimRight(string(content), "\x00 ")}
}

// GetProcessTree builds process tree string
func GetProcessTree(pid uint32, comm string) string {
	ppid := GetParentPID(pid)

	processMu.RLock()
	defer processMu.RUnlock()

	tree := comm
	parentTree, exists := processTree[ppid]
	if exists {
		tree = parentTree + " -> " + tree
	}

	return tree
}

// StoreProcess adds process to tree
func StoreProcess(pid uint32, tree string) {
	processMu.Lock()
	defer processMu.Unlock()
	processTree[pid] = tree
}

// RemoveProcess removes process from tree
func RemoveProcess(pid uint32) {
	processMu.Lock()
	defer processMu.Unlock()
	delete(processTree, pid)
}
