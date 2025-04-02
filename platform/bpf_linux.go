//go:build linux
package platform

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" netmonBPF ../bpf/netmon.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" execveBPF ../bpf/execve.c

import (
    "bytes"
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
    
    "bpf-recorder/binary"
    "bpf-recorder/database"
    "bpf-recorder/network"
    "bpf-recorder/process"
)

type LinuxBPFMonitor struct {
    db          *database.DB
    binaryCache *binary.Cache
    processMap  *process.ProcessMap
    cgroupPath  string
    stopChan    chan struct{}

    // Add BPF objects
    netmonObjs  netmonBPFObjects
    execveObjs  execveBPFObjects
}

func NewBPFMonitor(db *database.DB, binaryCache *binary.Cache, cgroupPath string) (BPFMonitor, error) {
    return &LinuxBPFMonitor{
        db:          db,
        binaryCache: binaryCache,
        processMap:  process.NewProcessMap(),
        cgroupPath:  cgroupPath,
        stopChan:    make(chan struct{}),
    }, nil
}

func (m *LinuxBPFMonitor) Start() error {
    // Remove resource limits
    if err := rlimit.RemoveMemlock(); err != nil {
        return fmt.Errorf("failed to remove memlock: %v", err)
    }

    if err := loadNetmonBPFObjects(&m.netmonObjs, nil); err != nil {
    	return fmt.Errorf("failed to load network eBPF objects: %v", err)
    }
    defer m.netmonObjs.Close()

    if err := loadExecveBPFObjects(&m.execveObjs, nil); err != nil {
    	return fmt.Errorf("failed to load process eBPF objects: %v", err)
    }
    defer m.execveObjs.Close()

    // Load network monitoring
    if err := loadNetmonBPFObjects(&m.netmonObjs, nil); err != nil {
        return fmt.Errorf("failed to load network eBPF objects: %v", err)
    }
    defer m.netmonObjs.Close()

    // Load process monitoring
    if err := loadExecveBPFObjects(&m.execveObjs, nil); err != nil {
        return fmt.Errorf("failed to load process eBPF objects: %v", err)
    }
    defer m.execveObjs.Close()

    // Attach to cgroup hooks for network monitoring
    cg1, err := link.AttachCgroup(link.CgroupOptions{
        Path:    m.cgroupPath,
        Attach:  ebpf.AttachCGroupInetSockCreate,
        Program: m.netmonObjs.CgroupSockCreate,
    })
    if err != nil {
        log.Printf("Warning: Failed to attach cgroup sock_create: %v", err)
    } else {
        defer cg1.Close()
    }

    cg2, err := link.AttachCgroup(link.CgroupOptions{
        Path:    m.cgroupPath,
        Attach:  ebpf.AttachCGroupInetIngress,
        Program: m.netmonObjs.CgroupSkbIngress,
    })
    if err != nil {
        log.Printf("Warning: Failed to attach cgroup ingress: %v", err)
    } else {
        defer cg2.Close()
    }

    cg3, err := link.AttachCgroup(link.CgroupOptions{
        Path:    m.cgroupPath,
        Attach:  ebpf.AttachCGroupInetEgress,
        Program: m.netmonObjs.CgroupSkbEgress,
    })
    if err != nil {
        log.Printf("Warning: Failed to attach cgroup egress: %v", err)
    } else {
        defer cg3.Close()
    }

    // Attach to syscalls and process events
    tpBind, err := link.Tracepoint("syscalls", "sys_enter_bind", m.netmonObjs.TraceBind, nil)
    if err != nil {
        log.Printf("Warning: Failed to attach bind tracepoint: %v", err)
    } else {
        defer tpBind.Close()
    }

    tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", m.execveObjs.TraceEnterExecve, nil)
    if err != nil {
        log.Printf("Warning: Failed to attach execve tracepoint: %v", err)
    } else {
        defer tpExec.Close()
    }

    tpExit, err := link.Tracepoint("sched", "sched_process_exit", m.execveObjs.TraceSchedProcessExit, nil)
    if err != nil {
        log.Printf("Warning: Failed to attach exit tracepoint: %v", err)
    } else {
        defer tpExit.Close()
    }

    // Create readers for each ringbuffer
    netReader, err := ringbuf.NewReader(m.netmonObjs.Events)
    if err != nil {
        return fmt.Errorf("failed to create network ringbuf reader: %v", err)
    }
    defer netReader.Close()

    procReader, err := ringbuf.NewReader(m.execveObjs.Events)
    if err != nil {
        return fmt.Errorf("failed to create process ringbuf reader: %v", err)
    }
    defer procReader.Close()

    // Use WaitGroups to ensure clean shutdown
    var wg sync.WaitGroup
    wg.Add(2) // One for each reader goroutine

    // Channel to signal readers to stop
    stop := make(chan struct{})

    log.Println("Starting BPF monitoring... Press Ctrl+C to exit")

    // Start network event reader goroutine
    go m.handleNetworkEvents(&wg, netReader, stop)

    // Start process event reader goroutine
    go m.handleProcessEvents(&wg, procReader, stop)

    // Wait for stop signal
    <-m.stopChan

    // Cleanup
    close(stop)
    wg.Wait()

    return nil
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
		    info.CmdLine = existingInfo.CmdLine      // Might as well copy other useful info
            	    info.ExePath = existingInfo.ExePath      // And the path
        	    info.ContainerID = existingInfo.ContainerID  // And container info if any

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
