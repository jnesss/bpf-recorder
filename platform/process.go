package platform

import (
	"bytes"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/jnesss/bpf-recorder/process"
)

// LookupCmdline retrieves the command line for a process from eBPF maps
func LookupCmdline(objs *execveBPFObjects, pid uint32) (string, error) {
	var cmdLine struct {
		Args [128]byte
	}

	// Try to lookup in the cmdlines map
	err := objs.Cmdlines.Lookup(pid, &cmdLine)
	if err != nil {
		return "", fmt.Errorf("failed to lookup cmdline: %v", err)
	}

	// Convert to string, handling null bytes
	cmdStr := make([]byte, 0, 128)
	for _, b := range cmdLine.Args {
		if b == 0 {
			break
		}
		cmdStr = append(cmdStr, b)
	}

	return string(cmdStr), nil
}

// EnrichProcessEvent adds additional information to a process event
func EnrichProcessEvent(event *ProcessEvent, processMap *process.ProcessMap, bpfObjs *execveBPFObjects) *process.ProcessInfo {
	pid := event.Pid

	// Get the basics from the kernel event
	info := &process.ProcessInfo{
		PID:      pid,
		PPID:     event.PPID,
		Comm:     string(bytes.TrimRight(event.Comm[:], "\x00")),
		UID:      event.UID,
		GID:      event.GID,
		ExitCode: event.ExitCode,
	}

	if event.EventType == EVENT_PROCESS_EXIT {
		info.ExitTime = time.Now() // not exactly right because it should be the event timestamp..
	} else if event.EventType == EVENT_PROCESS_EXEC {
		info.StartTime = time.Now()

		// Get kernel-mode command line
		var kernelCmdLine string
		if bpfObjs != nil {
			if cmdline, err := LookupCmdline(bpfObjs, pid); err == nil && cmdline != "" {
				kernelCmdLine = cmdline
				fmt.Printf("DEBUG: Kernel cmdline for PID %d: %s\n", pid, cmdline)
			}
		}

		// First immediate collection - might catch fast commands
		fmt.Printf("DEBUG: First proc check for PID %d\n", pid)
		firstProcExists := process.CollectProcMetadata(event.Pid, info)

		// Store initial proc-mode values
		initialPath := info.ExePath
		initialCmdline := info.CmdLine
		// initialComm := info.Comm
		initialWorkDir := info.WorkingDir

		if initialPath != "" {
			fmt.Printf("DEBUG: First proc exe_path for PID %d: %s\n", pid, initialPath)
		}
		if initialCmdline != "" {
			fmt.Printf("DEBUG: First proc cmdline for PID %d: %s\n", pid, initialCmdline)
		}
		if initialWorkDir != "" {
			fmt.Printf("DEBUG: First proc workdir for PID %d: %s\n", pid, initialWorkDir)
		}

		// Wait briefly for exec to complete
		time.Sleep(2 * time.Millisecond)

		// Second collection after exec should be complete
		fmt.Printf("DEBUG: Second proc check for PID %d\n", pid)
		secondProcExists := process.CollectProcMetadata(event.Pid, info)

		if info.ExePath != "" {
			fmt.Printf("DEBUG: Second proc exe_path for PID %d: %s\n", pid, info.ExePath)
		}
		if info.CmdLine != "" {
			fmt.Printf("DEBUG: Second proc cmdline for PID %d: %s\n", pid, info.CmdLine)
		}
		if info.WorkingDir != "" {
			fmt.Printf("DEBUG: Second proc workdir for PID %d: %s\n", pid, info.WorkingDir)
		}

		// Process name and path decision logic
		if !secondProcExists {
			if firstProcExists {
				info.ExePath = initialPath
				info.CmdLine = initialCmdline
				info.WorkingDir = initialWorkDir
				fmt.Printf("DEBUG: Using first proc values (second check failed) for PID %d\n", pid)
			} else {
				fmt.Printf("DEBUG: Using kernel values (no proc info) for PID %d\n", pid)
			}
		}

		// Always update comm from exe_path if we have one, regardless of which check gave it to us
		if info.ExePath != "" {
			info.Comm = filepath.Base(info.ExePath)
			fmt.Printf("DEBUG: Updated comm to %s from exe_path for PID %d\n", info.Comm, pid)
		}

		// Command line decision logic
		if info.CmdLine == "" {
			if initialCmdline != "" {
				fmt.Printf("DEBUG: Using first proc cmdline (no second proc) for PID %d\n", pid)
				info.CmdLine = initialCmdline
			} else if kernelCmdLine != "" {
				fmt.Printf("DEBUG: Using kernel cmdline (no proc) for PID %d\n", pid)
				info.CmdLine = kernelCmdLine
			}
		} else if info.CmdLine != initialCmdline {
			// Second proc check got different value than first - trust this one
			fmt.Printf("DEBUG: Using second proc cmdline (different from first) for PID %d\n", pid)
		} else if kernelCmdLine != "" && info.CmdLine != kernelCmdLine {
			// We have both kernel and proc values that differ
			if len(kernelCmdLine) > 16 && strings.HasPrefix(info.CmdLine, kernelCmdLine[:16]) {
				fmt.Printf("DEBUG: Using proc cmdline (matches kernel prefix) for PID %d\n", pid)
			} else {
				fmt.Printf("DEBUG: WARNING: kernel and proc cmdlines differ without matching prefix for PID %d\n", pid)
				fmt.Printf("DEBUG: Kernel: %s\n", kernelCmdLine)
				fmt.Printf("DEBUG: Proc  : %s\n", info.CmdLine)
				// Still prefer proc version as it's likely more complete
				fmt.Printf("DEBUG: Using proc version\n")
			}
		}

		// Get username if needed
		if info.Username == "" && info.UID > 0 {
			if u, err := user.LookupId(fmt.Sprintf("%d", info.UID)); err == nil {
				info.Username = u.Username
			}
		}

		// Get absolute path for ExePath if it's not already absolute
		if info.ExePath != "" && !filepath.IsAbs(info.ExePath) {
			oldPath := info.ExePath
			if info.WorkingDir != "" {
				info.ExePath = filepath.Join(info.WorkingDir, info.ExePath)
				fmt.Printf("DEBUG: Resolved relative path using workdir for PID %d: %s -> %s\n",
					pid, oldPath, info.ExePath)
			} else {
				// Try to resolve through PATH
				if path, err := exec.LookPath(info.ExePath); err == nil {
					info.ExePath = path
					fmt.Printf("DEBUG: Resolved relative path using PATH for PID %d: %s -> %s\n",
						pid, oldPath, info.ExePath)
				}
			}
		}
	}

	return info
}
