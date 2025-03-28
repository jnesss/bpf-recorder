# Detect OS
UNAME_S := $(shell uname -s)

# Default target
all: generate build

# Generate eBPF code (needed for Linux builds)
generate:
	go generate ./...

# OS-specific build commands
ifeq ($(UNAME_S),Darwin)
build:
	CGO_ENABLED=1 go build -tags darwin
else
build:
	go build
endif

# Clean build artifacts
clean:
	rm -f bpf-recorder
	rm -f *.o
