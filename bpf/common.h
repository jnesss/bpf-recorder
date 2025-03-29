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

// Enhanced event structure - must match the Go struct in reader.go
struct event {
    u32 pid;         // Process ID
    u32 ppid;        // Parent Process ID
    u64 timestamp;   // Timestamp in nanoseconds
    char comm[16];   // Process name
    char filename[64]; // Executable path
    int event_type;  // 1 = exec, 2 = exit
    int exit_code;   // Exit code for exit events    
    uid_t uid;       // User ID
    gid_t gid;       // Group ID
    char cwd[64];    // Current working directory
    char args[128];  // Command line arguments
    char parent_comm[16]; // Parent process name
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

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sched_process_template {
    unsigned long long unused;
    char comm[16];
    pid_t pid;
    int prio;
    int exit_code;
};

// Placeholder for Linux-specific structs
#if defined(__linux__)
// This will be included in Linux builds
struct task_struct;
struct cred;
#endif

#endif