#ifndef __COMMON_H
#define __COMMON_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 8192
#define ALLOW_PKT 1
#define ALLOW_SK 1

// Event types
#define EVENT_PROCESS_EXEC 1   // Process execution
#define EVENT_PROCESS_EXIT 2   // Process exit
#define EVENT_NET_CONNECT  3   // Network connect
#define EVENT_NET_ACCEPT   4   // Network accept
#define EVENT_NET_BIND     5   // Network bind

// Enhanced process event structure - matching old structure
struct process_event {
    __u32 event_type;          // Type of event
    __u32 pid;                 // Process ID
    __u64 timestamp;           // Event timestamp
    char comm[TASK_COMM_LEN];  // Process name
    __u32 ppid;                // Parent process ID (if available)
    __u32 uid;                 // User ID
    __u32 gid;                 // Group ID
    __u32 exit_code;           // Exit code (for exit events)
    
    // New fields
    char parent_comm[TASK_COMM_LEN]; // Parent process name
    char exe_path[64];               // Executable path
    __u32 flags;                     // Additional flags
};

// Network event structure
struct network_event {
    __u32 event_type;         // Type of event
    __u32 pid;                // Process ID
    __u64 timestamp;          // Event timestamp
    char comm[TASK_COMM_LEN]; // Process name
    __u32 saddr_a;            // Source IP address parts
    __u32 saddr_b;
    __u32 saddr_c;
    __u32 saddr_d;
    __u32 daddr_a;            // Destination IP address parts
    __u32 daddr_b;
    __u32 daddr_c;
    __u32 daddr_d;
    __u16 sport;              // Source port
    __u16 dport;              // Destination port
    __u8  protocol;           // Protocol (TCP/UDP)
};

// Socket info for tracking process info
struct sock_info {
    __u32 pid;
    char comm[TASK_COMM_LEN];
};

// Command line info structure - used in maps, not on stack
struct cmd_line {
    char args[128];           // Command line arguments (reduced size for BPF verifier)
};

#endif /* __COMMON_H */
