//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" netmonBPF bpf/netmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" execveBPF bpf/execve.c

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/jnesss/bpf-recorder/binary"
	"github.com/jnesss/bpf-recorder/database"
	"github.com/jnesss/bpf-recorder/platform"
	"github.com/jnesss/bpf-recorder/sigma"
	"github.com/jnesss/bpf-recorder/web"
)

const (
	DefaultDataDir  = "./data"
	DefaultBinsDir  = "./bins"
	DefaultRulesDir = "./rules"
)

func main() {
	// Parse command line flags
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "path to cgroup v2 mountpoint")
	dataDir := flag.String("data", DefaultDataDir, "Directory for storing data")
	binsDir := flag.String("bins", DefaultBinsDir, "Directory for binary storage")
	rulesDir := flag.String("rules", DefaultRulesDir, "Directory for Sigma rules")
	binCacheSize := flag.Int("bin-cache-size", 128, "Size of binary cache")
	flag.Parse()

	// Get non-root user for ownership
	runningUser, err := getRunningUser()
	if err != nil {
		log.Fatalf("Failed to get running user: %v", err)
	}

	// Create directories with correct permissions
	if err := setupDirectories(*dataDir, *binsDir, *rulesDir, runningUser); err != nil {
		log.Fatalf("Failed to setup directories: %v", err)
	}

	// Initialize binary cache
	binaryCache, err := binary.NewCache(*binCacheSize, *binsDir)
	if err != nil {
		log.Fatalf("Failed to initialize binary cache: %v", err)
	}

	// Initialize database
	//  This will cause database to be owned by root, which is ok for now
	db, err := database.NewDB(*dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize Sigma detector
	sigmaDetector, err := sigma.NewDetector(*rulesDir, db.Db)
	if err != nil {
		log.Printf("Warning: Failed to initialize Sigma detector: %v", err)
	} else {
		if err := sigmaDetector.StartPolling(10 * time.Second); err != nil {
			log.Printf("Warning: Failed to start Sigma detection: %v", err)
		}
		defer sigmaDetector.StopPolling()
	}

	// Start web server in background
	go func() {
		webserver := web.NewServer(db.Db, sigmaDetector, binaryCache, ":8080")
		if err := webserver.Start(); err != nil {
			log.Printf("Web server error: %v\n", err)
		}
	}()
	fmt.Println("Web interface available at http://localhost:8080")

	// Initialize and start BPF monitoring
	monitor, err := platform.NewBPFMonitor(db, binaryCache, *cgroupPath)
	if err != nil {
		log.Fatalf("Failed to initialize BPF monitor: %v", err)
	}

	if err := monitor.Start(); err != nil {
		log.Fatalf("Failed to start BPF monitor: %v", err)
	}
	defer monitor.Stop()

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\nShutting down gracefully...")
}

// getRunningUser gets the SUDO_USER or current user if not running with sudo
func getRunningUser() (*user.User, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		return user.Lookup(sudoUser)
	}
	return user.Current()
}

// chownPath changes ownership of a path to the specified user
func chownPath(path string, u *user.User) error {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid: %v", err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("invalid gid: %v", err)
	}

	return os.Chown(path, uid, gid)
}

// setupDirectories creates and sets ownership for all required directories
func setupDirectories(dataDir, binsDir, rulesDir string, u *user.User) error {
	// Create and chown data directory
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}
	if err := chownPath(dataDir, u); err != nil {
		return fmt.Errorf("failed to chown data directory: %v", err)
	}

	// Create and chown bins directory
	if err := os.MkdirAll(binsDir, 0755); err != nil {
		return fmt.Errorf("failed to create bins directory: %v", err)
	}
	if err := chownPath(binsDir, u); err != nil {
		return fmt.Errorf("failed to chown bins directory: %v", err)
	}

	// Create hash prefix subdirectories
	for i := 0; i < 256; i++ {
		prefix := fmt.Sprintf("%02x", i)
		binSubdir := filepath.Join(binsDir, prefix)
		if err := os.MkdirAll(binSubdir, 0755); err != nil {
			return fmt.Errorf("failed to create bin subdir %s: %v", prefix, err)
		}
		if err := chownPath(binSubdir, u); err != nil {
			return fmt.Errorf("failed to chown bin subdir %s: %v", prefix, err)
		}
	}

	// Create rules directory structure
	for _, dir := range []string{
		rulesDir,
		filepath.Join(rulesDir, "enabled_rules"),
		filepath.Join(rulesDir, "disabled_rules"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create rules directory %s: %v", dir, err)
		}
		if err := chownPath(dir, u); err != nil {
			return fmt.Errorf("failed to chown rules directory %s: %v", dir, err)
		}
	}

	return nil
}
