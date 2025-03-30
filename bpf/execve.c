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
    .value_size = 256,  // Start with 256 bytes for command line
    .max_entries = 1024,
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

    // Store just the executable path in our command line map
    // We'll use the PID as the key
    u32 pid = event.pid;
    event.cmdline_map_id = pid;  // Set the ID for userspace lookup

    // Create a buffer on the stack
    char buffer[256];
    __builtin_memset(buffer, 0, sizeof(buffer));
    
    // Position in buffer
    int offset = 0;
    
    // Get the arguments array
    const char **args = (const char **)(ctx->args[1]);

    // Loop through arguments to build command line string
    for (int i = 0; i < 10 && offset < sizeof(buffer) - 1; i++) {
        // Get the next argument
        const char *arg = NULL;
        bpf_probe_read(&arg, sizeof(arg), &args[i]);
    
        if (!arg)
            break;  // No more arguments
    
        // Add space between arguments (not before the first one)
        if (i > 0 && offset < sizeof(buffer) - 1) {
            buffer[offset++] = ' ';
        }
    
        // Read the argument into our buffer
        int bytes_read = bpf_probe_read_str(&buffer[offset], sizeof(buffer) - offset, arg);
    
        // If bytes_read is <= 0, something went wrong
        if (bytes_read <= 0)
            break;
    
        // Adjust offset, accounting for null terminator in bytes_read
        offset += (bytes_read - 1);
    }

    // Ensure null termination
    if (offset < sizeof(buffer))
        buffer[offset] = '\0';

    // Update the map with the buffer
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