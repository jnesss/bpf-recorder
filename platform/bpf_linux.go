//go:build linux

package platform

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" dnsmonBPF ../bpf/dnsmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" netmonBPF ../bpf/netmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" execveBPF ../bpf/execve.c

import (
	"bytes"
	"context"
	binenc "encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/jnesss/bpf-recorder/binary"
	"github.com/jnesss/bpf-recorder/database"
	"github.com/jnesss/bpf-recorder/network"
	"github.com/jnesss/bpf-recorder/process"
)

type LinuxBPFMonitor struct {
	db          *database.DB
	binaryCache *binary.Cache
	processMap  *process.ProcessMap
	cgroupPath  string
	stopChan    chan struct{}

	// Add BPF objects
	netmonObjs netmonBPFObjects
	execveObjs execveBPFObjects
	dnsmonObjs dnsmonBPFObjects // New DNS monitoring objects

	// Add trackers for DNS and TLS events
	dnsTracker *network.DNSMap
	tlsTracker *network.TLSMap

	// Rate limiting for console output
	lastLogTime  time.Time
	eventCounter uint64
	logMutex     sync.Mutex
}

func NewBPFMonitor(config *MonitorConfig) (BPFMonitor, error) {
	monitor := &LinuxBPFMonitor{
		db:          config.DB.(*database.DB),
		binaryCache: config.BinaryCache.(*binary.Cache),
		processMap:  config.ProcessMap,
		cgroupPath:  config.CgroupPath,
		stopChan:    make(chan struct{}),
		dnsTracker:  network.NewDNSMap(),
		tlsTracker:  network.NewTLSMap(),
		lastLogTime: time.Now(),
	}

	// Initialize any other components here

	return monitor, nil
}

// Add the new interface method
func (m *LinuxBPFMonitor) GetProcessMap() *process.ProcessMap {
	return m.processMap
}

func (m *LinuxBPFMonitor) Start(ctx context.Context) error {
	// Remove resource limits
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %v", err)
	}

	// Load network and process monitoring
	if err := loadNetmonBPFObjects(&m.netmonObjs, nil); err != nil {
		return fmt.Errorf("failed to load network eBPF objects: %v", err)
	}

	if err := loadExecveBPFObjects(&m.execveObjs, nil); err != nil {
		m.netmonObjs.Close()
		return fmt.Errorf("failed to load process eBPF objects: %v", err)
	}

	// Load DNS monitoring
	if err := loadDnsmonBPFObjects(&m.dnsmonObjs, nil); err != nil {
		m.netmonObjs.Close()
		m.execveObjs.Close()
		return fmt.Errorf("failed to load DNS eBPF objects: %v", err)
	}

	// Attach to cgroup hooks for network monitoring
	cg1, err := link.AttachCgroup(link.CgroupOptions{
		Path:    m.cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: m.netmonObjs.CgroupSockCreate,
	})
	if err != nil {
		log.Printf("Warning: Failed to attach cgroup sock_create: %v", err)
	}

	cg2, err := link.AttachCgroup(link.CgroupOptions{
		Path:    m.cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: m.netmonObjs.CgroupSkbIngress,
	})
	if err != nil {
		log.Printf("Warning: Failed to attach cgroup ingress: %v", err)
	}

	cg3, err := link.AttachCgroup(link.CgroupOptions{
		Path:    m.cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: m.netmonObjs.CgroupSkbEgress,
	})
	if err != nil {
		log.Printf("Warning: Failed to attach cgroup egress: %v", err)
	}

	// Attach to syscalls and process events
	tpBind, err := link.Tracepoint("syscalls", "sys_enter_bind", m.netmonObjs.TraceBind, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach bind tracepoint: %v", err)
	}

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", m.execveObjs.TraceEnterExecve, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach execve tracepoint: %v", err)
	}

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", m.execveObjs.TraceSchedProcessExit, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach exit tracepoint: %v", err)
	}

	// Create readers for each ringbuffer
	netReader, err := ringbuf.NewReader(m.netmonObjs.Events)
	if err != nil {
		return fmt.Errorf("failed to create network ringbuf reader: %v", err)
	}

	procReader, err := ringbuf.NewReader(m.execveObjs.Events)
	if err != nil {
		netReader.Close()
		return fmt.Errorf("failed to create process ringbuf reader: %v", err)
	}

	// Start DNS event reader
	dnsReader, err := ringbuf.NewReader(m.dnsmonObjs.Events)
	if err != nil {
		netReader.Close()
		procReader.Close()
		return fmt.Errorf("failed to create DNS ringbuf reader: %v", err)
	}

	// Create cleanup function
	cleanup := func() {
		if dnsReader != nil {
			dnsReader.Close()
		}
		if netReader != nil {
			netReader.Close()
		}
		if procReader != nil {
			procReader.Close()
		}
		if cg1 != nil {
			cg1.Close()
		}
		if cg2 != nil {
			cg2.Close()
		}
		if cg3 != nil {
			cg3.Close()
		}
		if tpBind != nil {
			tpBind.Close()
		}
		if tpExec != nil {
			tpExec.Close()
		}
		if tpExit != nil {
			tpExit.Close()
		}
		m.dnsmonObjs.Close()
		m.netmonObjs.Close()
		m.execveObjs.Close()
	}
	defer cleanup()

	// Use WaitGroups to ensure clean shutdown
	var wg sync.WaitGroup

	// Channel to signal readers to stop
	stop := make(chan struct{})

	// Start network event reader goroutine
	wg.Add(1)
	go m.handleNetworkEvents(&wg, netReader, stop)

	// Start process event reader goroutine
	wg.Add(1)
	go m.handleProcessEvents(&wg, procReader, stop)

	// Start DNS event reader goroutine
	wg.Add(1)
	go m.handleDNSEvents(&wg, dnsReader, stop)

	wg.Add(1)
	go m.handleTLSEvents(&wg, dnsReader, stop)

	log.Println("Starting BPF monitoring with DNS and TLS event tracking...  Press Ctrl+C to exit")

	// Wait for context cancellation or stop signal
	select {
	case <-ctx.Done():
		log.Println("Context cancelled, stopping BPF monitoring...")
	case <-m.stopChan:
		log.Println("Stop signal received, stopping BPF monitoring...")
	}

	// Signal readers to stop and wait for them to finish
	close(stop)

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("BPF monitoring stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Println("Warning: BPF monitoring shutdown timed out")
	}

	return nil
}

func (m *LinuxBPFMonitor) cleanup() {
	// Close BPF objects
	m.dnsmonObjs.Close()
	m.netmonObjs.Close()
	m.execveObjs.Close()
}

func (m *LinuxBPFMonitor) Stop() error {
	close(m.stopChan)
	return nil
}

func (m *LinuxBPFMonitor) handleNetworkEvents(wg *sync.WaitGroup, reader *ringbuf.Reader, stop chan struct{}) {
	defer wg.Done()

	for {
		select {
		case <-stop:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from network ring buffer: %v", err)
				continue
			}

			// Read common header first to determine event type
			var header EventHeader
			if err := binenc.Read(bytes.NewReader(record.RawSample), binenc.LittleEndian, &header); err != nil {
				log.Printf("Failed to parse event header: %v", err)
				continue
			}

			// Process network events
			var netEvent NetworkEvent
			if err := binenc.Read(bytes.NewReader(record.RawSample), binenc.LittleEndian, &netEvent); err != nil {
				log.Printf("Failed to parse network event: %v", err)
				continue
			}

			// Create source and destination IP addresses
			srcIP := net.IPv4(byte(netEvent.SAddrA), byte(netEvent.SAddrB),
				byte(netEvent.SAddrC), byte(netEvent.SAddrD))
			dstIP := net.IPv4(byte(netEvent.DAddrA), byte(netEvent.DAddrB),
				byte(netEvent.DAddrC), byte(netEvent.DAddrD))

			// Get process info and container ID
			proc, exists := m.processMap.Get(netEvent.Pid)
			containerID := ""
			if exists {
				containerID = proc.ContainerID
			}

			// Create connection info
			connInfo := network.CreateConnectionInfo(
				srcIP, dstIP,
				netEvent.SPort, netEvent.DPort,
				netEvent.Pid,
				string(bytes.TrimRight(netEvent.Comm[:], "\x00")),
				netEvent.Protocol,
				containerID,
			)

			// Insert into database
			if err := m.db.InsertNetworkConnection(connInfo, header.EventType); err != nil {
				log.Printf("Failed to insert network connection: %v", err)
			}

			output := network.FormatNetworkEvent(connInfo, header.EventType)
			fmt.Println(output)
		}
	}
}

func (m *LinuxBPFMonitor) handleProcessEvents(wg *sync.WaitGroup, reader *ringbuf.Reader, stop chan struct{}) {
	defer wg.Done()

	for {
		select {
		case <-stop:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from process ring buffer: %v", err)
				continue
			}

			var procEvent ProcessEvent
			if err := binenc.Read(bytes.NewReader(record.RawSample), binenc.LittleEndian, &procEvent); err != nil {
				log.Printf("Failed to parse process event: %v", err)
				continue
			}

			info := EnrichProcessEvent(&procEvent, m.processMap, &m.execveObjs)

			if procEvent.EventType == EVENT_PROCESS_EXEC {
				// Handle binary caching if we have a valid path
				if info.ExePath != "" && !strings.HasPrefix(info.ExePath, "/proc/") &&
					!strings.HasPrefix(info.ExePath, "/dev/") && !strings.HasPrefix(info.ExePath, "/sys/") {
					if hash, err := binary.CalculateMD5(info.ExePath); err == nil {
						info.BinaryMD5 = hash
						if !m.binaryCache.HasBinary(hash) {
							if err := m.binaryCache.StoreBinary(info.ExePath, hash); err != nil {
								log.Printf("Error storing binary %s: %v", info.ExePath, err)
							}
						}
					}
				}

				// Insert into database
				if err := m.db.InsertProcess(info); err != nil {
					log.Printf("Failed to insert process record: %v", err)
				}

				m.processMap.Add(procEvent.Pid, info)

				// Add formatted output
				output := process.FormatProcessEvent(info, procEvent.EventType)
				fmt.Println(output)

			} else if procEvent.EventType == EVENT_PROCESS_EXIT {
				if existingInfo, exists := m.processMap.Get(procEvent.Pid); exists {
					info.StartTime = existingInfo.StartTime
					info.ExitTime = time.Now()
					info.CmdLine = existingInfo.CmdLine         // Might as well copy other useful info
					info.ExePath = existingInfo.ExePath         // And the path
					info.ContainerID = existingInfo.ContainerID // And container info if any

					if err := m.db.UpdateProcessExit(info.PID, info.ExitCode, info.ExitTime); err != nil {
						// Don't log anything - duplicate updates will fail silently
					}

					// Add formatted output for exit
					output := process.FormatProcessEvent(info, procEvent.EventType)
					fmt.Println(output)

					m.processMap.Remove(procEvent.Pid)
				}
			}
		}
	}
}

// parse DNS events from the BPF ringbuffer
func (m *LinuxBPFMonitor) handleDNSEvents(wg *sync.WaitGroup, reader *ringbuf.Reader, stop chan struct{}) {
	defer wg.Done()

	// Create a database writer channel with buffering to prevent blocking
	dbWriteQueue := make(chan *network.DNSInfo, 1000)

	// Start a worker pool for database writes to avoid overwhelming the database
	const numWriters = 4
	var writerWg sync.WaitGroup
	writerWg.Add(numWriters)

	for i := 0; i < numWriters; i++ {
		go func() {
			defer writerWg.Done()
			for {
				select {
				case dnsInfo, ok := <-dbWriteQueue:
					if !ok {
						// Channel closed, exit
						return
					}

					// Write to database with retry logic
					var err error
					for retries := 0; retries < 3; retries++ {
						err = m.db.InsertDNSEvent(dnsInfo)
						if err == nil {
							break
						}
						// Exponential backoff before retry
						time.Sleep(time.Millisecond * time.Duration(10*(1<<retries)))
					}

					if err != nil {
						log.Printf("Failed to insert DNS event after retries: %v", err)
					}

				case <-stop:
					return
				}
			}
		}()
	}

	// Cleanup function to ensure we close channels
	defer func() {
		close(dbWriteQueue)

		// Wait for writers to finish with timeout
		done := make(chan struct{})
		go func() {
			writerWg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Println("DNS event writers shut down gracefully")
		case <-time.After(5 * time.Second):
			log.Println("Timeout waiting for DNS event writers to shut down")
		}
	}()

	// Main event processing loop
	for {
		select {
		case <-stop:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from DNS ring buffer: %v", err)
				continue
			}

			// Read common header first to determine event type
			var header EventHeader
			if err := binenc.Read(bytes.NewReader(record.RawSample), binenc.LittleEndian, &header); err != nil {
				log.Printf("Failed to parse event header: %v", err)
				continue
			}

			// Process DNS events
			if header.EventType == EVENT_DNS {
				var dnsEvent DNSEvent
				if err := binenc.Read(bytes.NewReader(record.RawSample), binenc.LittleEndian, &dnsEvent); err != nil {
					log.Printf("Failed to parse DNS event: %v", err)
					continue
				}

				// Create source and destination IP addresses
				srcIP := net.IPv4(byte(dnsEvent.SAddrA), byte(dnsEvent.SAddrB),
					byte(dnsEvent.SAddrC), byte(dnsEvent.SAddrD))
				dstIP := net.IPv4(byte(dnsEvent.DAddrA), byte(dnsEvent.DAddrB),
					byte(dnsEvent.DAddrC), byte(dnsEvent.DAddrD))

				// Get process info and container ID
				proc, exists := m.processMap.Get(dnsEvent.Pid)
				containerID := ""
				if exists {
					containerID = proc.ContainerID
				}

				// Create DNS info
				dnsInfo := network.CreateDNSInfo(
					srcIP, dstIP,
					dnsEvent.SPort, dnsEvent.DPort,
					dnsEvent.Pid,
					string(bytes.TrimRight(dnsEvent.Comm[:], "\x00")),
					containerID,
					dnsEvent.Txid,
					string(bytes.TrimRight(dnsEvent.QueryName[:], "\x00")),
					dnsEvent.QueryType,
					dnsEvent.IsResponse == 1,
					dnsEvent.Flags,
					dnsEvent.QuestionCount,
					dnsEvent.AnswerCount,
				)

				// Add to DNS tracker (which now handles correlation with the LRU cache)
				m.dnsTracker.AddDNSEvent(dnsInfo)

				// Non-blocking send to database writer queue
				select {
				case dbWriteQueue <- dnsInfo:
					// Successfully queued
				default:
					// Queue is full, log and continue without blocking
					log.Printf("Warning: DNS event queue full, dropping event")
				}

				// Add formatted output for console logging (with rate limiting)
				if rand.Intn(100) < 10 { // Only log ~10% of events to prevent console flooding
					output := network.FormatDNSEvent(dnsInfo)
					fmt.Println(output)
				}
			} else if header.EventType == EVENT_TLS {
				// Process TLS events similarly...
				// (TLS event processing code would go here similar to the DNS pattern)
			}
		}
	}
}

func (m *LinuxBPFMonitor) rateLimit() bool {
	m.logMutex.Lock()
	defer m.logMutex.Unlock()

	m.eventCounter++

	// Log once per second at most
	if time.Since(m.lastLogTime) > time.Second {
		m.lastLogTime = time.Now()
		count := m.eventCounter
		m.eventCounter = 0

		// Log total event count for the last second
		if count > 0 {
			log.Printf("Processed %d events in the last second", count)
		}

		return true
	}

	// Only log every Nth event to prevent flooding
	// For high-volume events, we'll log approximately 1% of events
	return (m.eventCounter % 100) == 0
}

// Add a method to handle logging based on current event rate
func (m *LinuxBPFMonitor) shouldLog(eventType string) bool {
	switch eventType {
	case "dns":
		// DNS events can be very high volume, use stricter rate limiting
		return (m.eventCounter%200) == 0 || m.rateLimit()
	case "tls":
		// TLS events are usually less frequent, use moderate rate limiting
		return (m.eventCounter%50) == 0 || m.rateLimit()
	case "network":
		// Regular network events, use standard rate limiting
		return (m.eventCounter%100) == 0 || m.rateLimit()
	default:
		// For other event types, use moderate rate limiting
		return (m.eventCounter%50) == 0 || m.rateLimit()
	}
}

func (m *LinuxBPFMonitor) handleTLSEvents(wg *sync.WaitGroup, reader *ringbuf.Reader, stop chan struct{}) {
	defer wg.Done()

	// Create a database writer channel with buffering to prevent blocking
	dbWriteQueue := make(chan *network.TLSInfo, 1000)

	// Start a worker pool for database writes to avoid overwhelming the database
	const numWriters = 4
	var writerWg sync.WaitGroup
	writerWg.Add(numWriters)

	for i := 0; i < numWriters; i++ {
		go func() {
			defer writerWg.Done()
			for {
				select {
				case tlsInfo, ok := <-dbWriteQueue:
					if !ok {
						// Channel closed, exit
						return
					}

					// Write to database with retry logic
					var err error
					for retries := 0; retries < 3; retries++ {
						err = m.db.InsertTLSEvent(tlsInfo)
						if err == nil {
							break
						}
						// Exponential backoff before retry
						time.Sleep(time.Millisecond * time.Duration(10*(1<<retries)))
					}

					if err != nil {
						log.Printf("Failed to insert TLS event after retries: %v", err)
					}

				case <-stop:
					return
				}
			}
		}()
	}

	// Cleanup function to ensure we close channels
	defer func() {
		close(dbWriteQueue)

		// Wait for writers to finish with timeout
		done := make(chan struct{})
		go func() {
			writerWg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Println("TLS event writers shut down gracefully")
		case <-time.After(5 * time.Second):
			log.Println("Timeout waiting for TLS event writers to shut down")
		}
	}()

	// Main event processing loop
	for {
		select {
		case <-stop:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from TLS ring buffer: %v", err)
				continue
			}

			// Read common header first to determine event type
			var header EventHeader
			if err := binenc.Read(bytes.NewReader(record.RawSample), binenc.LittleEndian, &header); err != nil {
				log.Printf("Failed to parse event header: %v", err)
				continue
			}

			// Process TLS events
			if header.EventType == EVENT_TLS {
				var tlsEvent TLSEvent
				if err := binenc.Read(bytes.NewReader(record.RawSample), binenc.LittleEndian, &tlsEvent); err != nil {
					log.Printf("Failed to parse TLS event: %v", err)
					continue
				}

				// Create source and destination IP addresses
				srcIP := net.IPv4(byte(tlsEvent.SAddrA), byte(tlsEvent.SAddrB),
					byte(tlsEvent.SAddrC), byte(tlsEvent.SAddrD))
				dstIP := net.IPv4(byte(tlsEvent.DAddrA), byte(tlsEvent.DAddrB),
					byte(tlsEvent.DAddrC), byte(tlsEvent.DAddrD))

				// Get process info and container ID
				proc, exists := m.processMap.Get(tlsEvent.Pid)
				containerID := ""
				if exists {
					containerID = proc.ContainerID
				}

				// Extract cipher suites (simplified with fixed array in this version)
				cipherSuites := []uint16{}
				if tlsEvent.CipherLen > 0 && tlsEvent.CipherLen <= 8 {
					for i := 0; i < int(tlsEvent.CipherLen); i++ {
						cipherSuites = append(cipherSuites, tlsEvent.Ciphers[i])
					}
				}

				// Create TLS info
				tlsInfo := network.CreateTLSInfo(
					srcIP, dstIP,
					tlsEvent.SPort, tlsEvent.DPort,
					tlsEvent.Pid,
					string(bytes.TrimRight(tlsEvent.Comm[:], "\x00")),
					containerID,
					tlsEvent.TlsVersion,
					tlsEvent.HandshakeType,
					string(bytes.TrimRight(tlsEvent.Sni[:], "\x00")),
					cipherSuites,
				)

				// Add to TLS tracker with automatic LRU management
				m.tlsTracker.AddTLSEvent(tlsInfo)

				// Non-blocking send to database writer queue
				select {
				case dbWriteQueue <- tlsInfo:
					// Successfully queued
				default:
					// Queue is full, log and continue without blocking
					log.Printf("Warning: TLS event queue full, dropping event")
				}

				// Rate-limited console logging
				if m.shouldLog("tls") {
					output := network.FormatTLSEvent(tlsInfo)
					fmt.Println(output)
				}
			}
		}
	}
}
