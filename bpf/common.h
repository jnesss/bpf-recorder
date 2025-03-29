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

// Enhanced event structure with inline command line
struct event {
    // 8-byte aligned fields
    u64 timestamp;   // 8 bytes
    
    // 4-byte aligned fields
    u32 pid;         // 4 bytes
    u32 ppid;        // 4 bytes
    uid_t uid;       // 4 bytes
    gid_t gid;       // 4 bytes
    int event_type;  // 4 bytes
    int exit_code;   // 4 bytes
    
    // Variable-length fields
    char comm[16];           // Process name
    char parent_comm[16];    // Parent process name
    char filename[64];       // Executable path
    char cwd[64];            // Current working directory
    
    // Command line in the structure
    char cmdline[128];       // Command line (inline for most cases)
    u32 cmdline_len;         // Length of command line
    u8 is_truncated;         // Flag to indicate truncation
    u8 _pad[3];              // Padding to ensure alignment
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

// Placeholder for Linux-specific structs
#if defined(__linux__)
// This will be included in Linux builds
struct task_struct;
struct cred;
#endif

#endif