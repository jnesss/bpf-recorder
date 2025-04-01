#ifndef __COMMON_H
#define __COMMON_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

// Define uid_t and gid_t
typedef u32 uid_t;
typedef u32 gid_t;

// Define pid_t 
typedef int pid_t;

// Event types
#define EVENT_EXEC     1  // Process execution
#define EVENT_EXIT     2  // Process exit
#define EVENT_CONNECT  3  // Network connect
#define EVENT_ACCEPT   4  // Network accept
#define EVENT_BIND     5  // Network bind

// Enhanced event structure with inline command line
struct process_event {
    u64 timestamp;   // 8 bytes
    
    // 4-byte aligned fields
    u32 event_type;  // 4 bytes - Using the defines above
    u32 pid;         // 4 bytes
    u32 ppid;        // 4 bytes
    uid_t uid;       // 4 bytes
    gid_t gid;       // 4 bytes
    int exit_code;   // 4 bytes
    u32 flags;       // 4 bytes
    
    // Variable-length fields
    char comm[16];           // Process name
    char parent_comm[16];    // Parent process name
    char filename[64];       // Executable path
    char cwd[64];            // Current working directory
    
    // For command line tracking
    u32 cmdline_map_id;      // ID to lookup command line in the map
    
} __attribute__((packed));

// Network event structure for tracking connections
struct network_event {
    u64 timestamp;   // 8 bytes
  
    // 4-byte aligned fields
    u32 event_type;           // 4 bytes - Using the defines above
    u32 pid;                  // 4 bytes - Process ID
    u32 ppid;                 // 4 bytes - Parent process ID
    uid_t uid;                // 4 bytes - User ID
    gid_t gid;                // 4 bytes - Group ID
    u32 src_addr_v4;          // 4 bytes - Source IPv4 address
    u32 dst_addr_v4;          // 4 bytes - Destination IPv4 address
    u16 src_port;             // 2 bytes - Source port
    u16 dst_port;             // 2 bytes - Destination port
    u8  ip_version;           // 1 byte  - IP version (4 or 6)
    u8  protocol;             // 1 byte  - Protocol (TCP, UDP, etc.)
    u8  operation;            // 1 byte  - Operation type (connect, accept, bind)
    u8  padding;              // 1 byte  - Padding for alignment
    int return_code;          // 4 bytes - Syscall return code
    
    // Variable-length fields
    char comm[16];            // Process name
    char parent_comm[16];     // Parent process name
    char exe_path[64];        // Executable path
    
    // IPv6 addresses (if applicable)
    u32 src_addr_v6[4];       // 16 bytes - Source IPv6 address
    u32 dst_addr_v6[4];       // 16 bytes - Destination IPv6 address
} __attribute__((packed));

/* BPF map definition struct */
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

/* Map types - corresponds to enum bpf_map_type */
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4

// Network operation types
#define NET_OPERATION_CONNECT  1
#define NET_OPERATION_ACCEPT   2
#define NET_OPERATION_BIND     3

// Network protocol types
#define NET_PROTOCOL_TCP      6   // Matches IPPROTO_TCP
#define NET_PROTOCOL_UDP     17   // Matches IPPROTO_UDP


// Placeholder for Linux-specific structs
#if defined(__linux__)
// This will be included in Linux builds
struct task_struct;
struct cred;
#endif

#endif