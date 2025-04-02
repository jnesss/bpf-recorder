# Variables
PROGNAME := bpf-recorder
BPFDIR := bpf
GO := go
SUDO := sudo
CGROUP_PATH := /sys/fs/cgroup

# Build flags
GOFLAGS := -v

# Default target
.PHONY: all
all: build

# Generate eBPF code
.PHONY: generate
generate:
	@echo "Generating eBPF code..."
	$(GO) generate ./...

# Build the program
.PHONY: build
build: generate
	@echo "Building $(PROGNAME)..."
	$(GO) build $(GOFLAGS) -o $(PROGNAME)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(PROGNAME)
	rm -f netmonbpf_*.go
	rm -f netmonbpf_*.o
	rm -f execvebpf_*.go
	rm -f execvebpf_*.o

# Run the program with sudo
.PHONY: run
run: build
	@echo "Running $(PROGNAME) with sudo..."
	$(SUDO) ./$(PROGNAME) -cgroup $(CGROUP_PATH)

# Install required dependencies (for Amazon Linux 2023)
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	sudo dnf install -y clang llvm libbpf-devel kernel-headers make git

# Initialize Go module (if needed)
.PHONY: init
init:
	@echo "Initializing Go module..."
	$(GO) mod init bpf-recorder
	$(GO) get github.com/cilium/ebpf@latest

# Help message
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all       - Build the program (default)"
	@echo "  generate  - Generate eBPF code from C files"
	@echo "  build     - Build the program"
	@echo "  clean     - Remove build artifacts"
	@echo "  run       - Build and run the program with sudo"
	@echo "  deps      - Install required dependencies"
	@echo "  init      - Initialize Go module (if needed)"
	@echo "  help      - Show this help message"
