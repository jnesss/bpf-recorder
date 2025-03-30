//go:build ignore

#include "amazon_linux_2023_kernel_6_1_vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"  // Include common.h for structure definitions

char __license[] SEC("license") = "Dual MIT/GPL";

// Define the events map
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 128,
    .map_flags = 0,
};

// Define a map for command lines keyed by PID
struct bpf_map_def SEC("maps") cmdlines = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = 512,  // Command line buffer size
    .max_entries = 1024,
    .map_flags = 0,
};

// Define a per-CPU array for our command line buffer
struct bpf_map_def SEC("maps") cmdline_buffer = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = 512,
    .max_entries = 1,
    .map_flags = 0,
};

// Handle process execution with enhanced metadata
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
    struct event event = {0};
    
    // Basic process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 1; // EXEC event
    
    // Get task_struct using helper
    void *task = bpf_get_current_task();
    
    // Get parent PID using correct offsets
    u32 ppid = 0;
    void *parent = NULL;
    bpf_probe_read(&parent, sizeof(parent), task + 2496); // Exact offset to real_parent
    if (parent) {
        bpf_probe_read(&ppid, sizeof(ppid), parent + 2484); // Exact offset to tgid
        bpf_probe_read_str(&event.parent_comm, sizeof(event.parent_comm), parent + 3040); // Exact offset to comm
    }
    event.ppid = ppid;
    
    // Get UID/GID using helper function
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid & 0xffffffff;
    event.gid = uid_gid >> 32;
    
    // Get filename (executable path)
    const char* filename = (const char*)ctx->args[0];
    bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);

    // Store PID as map ID for userspace lookup
    u32 pid = event.pid;
    event.cmdline_map_id = pid;
    
    // Use a per-CPU array instead of stack buffer
    u32 zero = 0;
    char *buffer = bpf_map_lookup_elem(&cmdline_buffer, &zero);
    if (!buffer)
        return 0;  // Can't proceed without buffer
    
    // Initialize buffer to zeros
    __builtin_memset(buffer, 0, 512);

    // Get the arguments array
    const char **args = (const char **)(ctx->args[1]);

    // Track our position in the buffer
    int offset = 0;

    // Handle each argument separately with fixed positions
    // Arg 0
    const char *arg0 = NULL;
    bpf_probe_read(&arg0, sizeof(arg0), &args[0]);
    if (arg0) {
        int bytes = bpf_probe_read_str(&buffer[0], 64, arg0);
        if (bytes > 0) {
            offset = bytes - 1; // Account for null terminator
        }
    }

    // Process 10 more arguments with fixed offsets
    #define PROCESS_ARG(n, max_len) \
        if (offset < 500) { \
            const char *arg ## n = NULL; \
            bpf_probe_read(&arg ## n, sizeof(arg ## n), &args[n]); \
            if (arg ## n) { \
                buffer[offset] = ' '; \
                offset++; \
                int bytes = bpf_probe_read_str(&buffer[offset], max_len, arg ## n); \
                if (bytes > 0) { \
                    offset += (bytes - 1); \
                } \
            } \
        }

    // Process args 1-19 with fixed sizes 
    //  we are using this roundabout macro approachto satisfy BPF verifier
    PROCESS_ARG(1, 48)
    PROCESS_ARG(2, 48)
    PROCESS_ARG(3, 48)
    PROCESS_ARG(4, 48)
    PROCESS_ARG(5, 48)
    PROCESS_ARG(6, 32)
    PROCESS_ARG(7, 32)
    PROCESS_ARG(8, 32)
    PROCESS_ARG(9, 32)
    PROCESS_ARG(10, 24)
    PROCESS_ARG(11, 16)
    PROCESS_ARG(12, 16)
    PROCESS_ARG(13, 16)
    PROCESS_ARG(14, 12)
    PROCESS_ARG(15, 12)
    PROCESS_ARG(16, 8)
    PROCESS_ARG(17, 8)
    PROCESS_ARG(18, 8)
    PROCESS_ARG(19, 8)

    // Ensure null termination
    buffer[511] = '\0';

    // Update the cmdlines map with the buffer
    bpf_map_update_elem(&cmdlines, &pid, buffer, BPF_ANY);
    
    // Working directory placeholder
    const char *fake_cwd = "/";
    bpf_probe_read_str(&event.cwd, sizeof(event.cwd), fake_cwd);
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Handle process exit
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template* ctx) {
    struct event event = {0};
    
    // Basic process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 2; // EXIT event
    
    event.exit_code = 0;
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}