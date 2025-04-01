//go:build ignore

#include "amazon_linux_2023_kernel_6_1_vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* Define missing socket constants */
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

/* Define always_inline if missing */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* Define PT_REGS_* macros for accessing function parameters */
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_RC(x) ((x)->ax)

// Define the network events perf buffer
struct bpf_map_def SEC("maps") network_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 128,
    .map_flags = 0,
};

// Connection state tracking map (pid -> socket info)
struct bpf_map_def SEC("maps") connection_state = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),     // PID as key
    .value_size = sizeof(struct network_event),
    .max_entries = 1024,
    .map_flags = 0,
};

// Helper to extract IPv4 socket information
static __always_inline int extract_ipv4_info(struct sockaddr_in *addr, u32 *ip, u16 *port) {
    if (!addr)
        return -1;
    
    // Extract IP and port (port needs byte swap)
    bpf_probe_read(ip, sizeof(u32), &addr->sin_addr.s_addr);
    bpf_probe_read(port, sizeof(u16), &addr->sin_port);
    *port = __builtin_bswap16(*port); // Convert from network to host byte order
    
    return 0;
}

// Helper to extract IPv6 socket information
static __always_inline int extract_ipv6_info(struct sockaddr_in6 *addr, u32 *ip, u16 *port) {
    if (!addr)
        return -1;
    
    // Extract IPv6 address (16 bytes = 4 u32 array)
    bpf_probe_read(ip, sizeof(u32) * 4, &addr->sin6_addr);
    
    // Extract port (needs byte swap)
    bpf_probe_read(port, sizeof(u16), &addr->sin6_port);
    *port = __builtin_bswap16(*port); // Convert from network to host byte order
    
    return 0;
}

// Helper to get socket family
static __always_inline int get_socket_family(struct sockaddr *addr) {
    u16 family;
    bpf_probe_read(&family, sizeof(family), &addr->sa_family);
    return family;
}

// Helper to determine protocol from socket
static __always_inline int get_socket_protocol(int sockfd) {
    // Unfortunately, we can't easily get the protocol from just the socket FD
    // in eBPF. We would need to walk kernel structures, which is difficult
    // and potentially unreliable. Let's simplify for now.
    return 0; // Unknown by default, will be filled in userspace
}

// Common function to fill basic process information
static __always_inline void fill_process_info(struct network_event *event) {
    // Set header fields - timestamp and event_type will be set by the caller
    event->header.timestamp = bpf_ktime_get_ns();
    
    // Basic process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Get task_struct using helper
    void *task = bpf_get_current_task();
    
    // Get parent PID using correct offsets
    u32 ppid = 0;
    void *parent = NULL;
    bpf_probe_read(&parent, sizeof(parent), task + 2496); // Exact offset to real_parent
    if (parent) {
        bpf_probe_read(&ppid, sizeof(ppid), parent + 2484); // Exact offset to tgid
        bpf_probe_read(&event->parent_comm, sizeof(event->parent_comm), parent + 3040); // Exact offset to comm
    }
    event->ppid = ppid;
    
    // Get UID/GID using helper function
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xffffffff;
    event->gid = uid_gid >> 32;
    
    // Get executable path from mm->exe_file (similar to execve.c)
    void *mm = NULL;
    bpf_probe_read(&mm, sizeof(mm), task + 2336); // kernel 6.1 mm offset

    if (mm) {
        void *exe_file = NULL;
        bpf_probe_read(&exe_file, sizeof(exe_file), mm + 880); // kernel 6.1 exe_file offset
    
        if (exe_file) {
            // We can't easily extract the full path in eBPF
            // Just mark that we have a valid exe
            char dummy[1];
            bpf_probe_read(&dummy, sizeof(dummy), exe_file);
            if (dummy[0]) {
                // Just to make verifier happy
                event->exe_path[0] = '/';
            }
        }
    }
}

// kprobe for connect() syscall entry
SEC("kprobe/SyS_connect")
int kprobe__sys_connect(struct pt_regs *ctx) {
    int sockfd = (int)PT_REGS_PARM1(ctx);
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    
    // Prepare event
    struct network_event event = {0};
    
    // Skip if socket address is NULL
    if (!addr)
        return 0;
    
    // Fill basic process info
    fill_process_info(&event);
    
    // Set the event type in the header
    event.header.event_type = EVENT_CONNECT;
    
    // Set operation type
    event.operation = NET_OPERATION_CONNECT;
    
    // Get socket family
    u16 family;
    bpf_probe_read(&family, sizeof(family), &addr->sa_family);
    
    // Process based on socket family
    if (family == AF_INET) {
        // IPv4
        event.ip_version = 4;
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        extract_ipv4_info(addr_in, &event.dst_addr_v4, &event.dst_port);
        
        // Set source address as local IP (will be filled by post-connect)
        event.src_addr_v4 = 0;
        event.src_port = 0;
    }
    else if (family == AF_INET6) {
        // IPv6
        event.ip_version = 6;
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        extract_ipv6_info(addr_in6, event.dst_addr_v6, &event.dst_port);
        
        // Set source address as local IP (will be filled by post-connect)
        __builtin_memset(event.src_addr_v6, 0, sizeof(event.src_addr_v6));
        event.src_port = 0;
    }
    else {
        // Not an IPv4/IPv6 connection, skip
        return 0;
    }
    
    // Try to determine protocol (simplified)
    event.protocol = NET_PROTOCOL_TCP; // Assume TCP by default
    
    // Store the event for post-connect processing
    u32 pid = event.pid;
    bpf_map_update_elem(&connection_state, &pid, &event, BPF_ANY);
    
    return 0;
}

// kretprobe for connect() syscall return
SEC("kretprobe/SyS_connect")
int kretprobe__sys_connect(struct pt_regs *ctx) {
    // Get return value
    int ret = PT_REGS_RC(ctx);
    
    // Get current PID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Look up the connection state
    struct network_event *event = bpf_map_lookup_elem(&connection_state, &pid);
    if (!event)
        return 0;
    
    // Set return code
    event->return_code = ret;
    
    // Submit the event to userspace
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    
    // Clean up state
    bpf_map_delete_elem(&connection_state, &pid);
    
    return 0;
}

// kprobe for accept() and accept4() syscalls
SEC("kprobe/SyS_accept")
int kprobe__sys_accept(struct pt_regs *ctx) {
    // Similar to connect but for inbound connections
    int sockfd = (int)PT_REGS_PARM1(ctx);
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    
    // Skip if socket address is NULL
    if (!addr)
        return 0;
    
    // Prepare a partial event (will be completed in the return probe)
    struct network_event event = {0};
    
    // Fill basic process info
    fill_process_info(&event);
    
    // Set the event type in the header
    event.header.event_type = EVENT_ACCEPT;
    
    // Set operation type
    event.operation = NET_OPERATION_ACCEPT;
    
    // Store the socket file descriptor for the return probe
    u32 pid = event.pid;
    bpf_map_update_elem(&connection_state, &pid, &event, BPF_ANY);
    
    return 0;
}

// kretprobe for accept() syscall
SEC("kretprobe/SyS_accept")
int kretprobe__sys_accept(struct pt_regs *ctx) {
    // Get return value (the new socket fd)
    int sockfd = PT_REGS_RC(ctx);
    
    // Skip if accept failed
    if (sockfd < 0)
        return 0;
    
    // Get current PID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Look up the connection state
    struct network_event *event = bpf_map_lookup_elem(&connection_state, &pid);
    if (!event)
        return 0;
    
    // Set return code
    event->return_code = sockfd; // success = new socket fd
    
    // Try to determine protocol (simplified)
    event->protocol = NET_PROTOCOL_TCP; // Assume TCP for accept by default
    
    // Submit the event to userspace
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    
    // Clean up state
    bpf_map_delete_elem(&connection_state, &pid);
    
    return 0;
}

// kprobe for bind() syscall
SEC("kprobe/SyS_bind")
int kprobe__sys_bind(struct pt_regs *ctx) {
    int sockfd = (int)PT_REGS_PARM1(ctx);
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    
    // Skip if socket address is NULL
    if (!addr)
        return 0;
    
    // Prepare event
    struct network_event event = {0};
    
    // Fill basic process info
    fill_process_info(&event);
    
    // Set the event type in the header
    event.header.event_type = EVENT_BIND;
    
    // Set operation type
    event.operation = NET_OPERATION_BIND;
    
    // Get socket family
    u16 family;
    bpf_probe_read(&family, sizeof(family), &addr->sa_family);
    
    // Process based on socket family
    if (family == AF_INET) {
        // IPv4
        event.ip_version = 4;
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        extract_ipv4_info(addr_in, &event.src_addr_v4, &event.src_port);
    }
    else if (family == AF_INET6) {
        // IPv6
        event.ip_version = 6;
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        extract_ipv6_info(addr_in6, event.src_addr_v6, &event.src_port);
    }
    else {
        // Not an IPv4/IPv6 socket, skip
        return 0;
    }
    
    // Try to determine protocol (simplified)
    event.protocol = NET_PROTOCOL_TCP; // Assume TCP by default
    
    // Store the event for post-bind processing
    u32 pid = event.pid;
    bpf_map_update_elem(&connection_state, &pid, &event, BPF_ANY);
    
    return 0;
}

// kretprobe for bind() syscall return
SEC("kretprobe/SyS_bind")
int kretprobe__sys_bind(struct pt_regs *ctx) {
    // Get return value
    int ret = PT_REGS_RC(ctx);
    
    // Get current PID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Look up the connection state
    struct network_event *event = bpf_map_lookup_elem(&connection_state, &pid);
    if (!event)
        return 0;
    
    // Set return code
    event->return_code = ret;
    
    // Submit the event to userspace
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    
    // Clean up state
    bpf_map_delete_elem(&connection_state, &pid);
    
    return 0;
}