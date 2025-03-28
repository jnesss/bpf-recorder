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

// Define pid_t 
typedef int pid_t;

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

#endif

