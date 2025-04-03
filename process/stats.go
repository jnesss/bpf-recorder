package process

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
)

// StatsCollector manages periodic collection of process statistics
type StatsCollector struct {
	storage            StatsStorage
	processMap         *ProcessMap
	collectionInterval time.Duration
}

// NewStatsCollector creates a new stats collector
func NewStatsCollector(storage StatsStorage, processMap *ProcessMap, interval time.Duration) *StatsCollector {
	return &StatsCollector{
		storage:            storage,
		processMap:         processMap,
		collectionInterval: interval,
	}
}

// Start begins periodic collection of process statistics
func (sc *StatsCollector) Start(ctx context.Context) error {
	ticker := time.NewTicker(sc.collectionInterval)
	defer ticker.Stop()

	log.Printf("Starting process stats collection every %v", sc.collectionInterval)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := sc.collectStats(); err != nil {
				log.Printf("Error collecting process stats: %v", err)
			}
		}
	}
}

// collectStats gathers current statistics for all running processes
func (sc *StatsCollector) collectStats() error {
	// Get processes from our ProcessMap
	processes := sc.processMap.List()

	for _, proc := range processes {
		// Skip if process has already exited
		if !proc.ExitTime.IsZero() {
			continue
		}

		// Check if process still exists
		if !processExists(proc.PID) {
			// Process has terminated but we missed the exit event
			// We could optionally handle this case
			continue
		}

		// Create new stats object
		stats := &ProcessStats{
			Timestamp: time.Now(),
		}

		// Collect CPU usage
		if cpuUsage, err := getCPUUsage(proc.PID); err == nil {
			stats.CPUUsage = cpuUsage
		}

		// Collect memory usage
		if memBytes, memPercent, err := getMemoryUsage(proc.PID); err == nil {
			stats.MemoryUsage = memBytes
			stats.MemoryPercent = memPercent
		}

		// Collect thread count
		if threadCount, err := getThreadCount(proc.PID); err == nil {
			stats.ThreadCount = threadCount
		}

		// Collect file descriptors and open files
		if fdCount, openFiles, err := getFileDescriptors(proc.PID); err == nil {
			stats.FileDescCount = fdCount
			stats.OpenFiles = openFiles
		}

		// Check for working directory changes
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", proc.PID)); err == nil {
			if cwd != proc.WorkingDir {
				proc.WorkingDir = cwd
				proc.WorkingDirHistory = append(proc.WorkingDirHistory, cwd)
			}
		}

		// Update stats in ProcessInfo
		proc.Stats = stats

		// Update database if needed
		if err := sc.storage.UpdateProcessStats(proc.PID, stats); err != nil {
			log.Printf("Error updating stats for PID %d: %v", proc.PID, err)
		}
	}

	return nil
}

// processExists checks if a process still exists
func processExists(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return !os.IsNotExist(err)
}
