//go:build ignore

#include "amazon_linux_2023_kernel_6_1_vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Define the map structure type
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;  // Add the map_flags field for toolchain
};

// Define the events map using the structure
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 128,
    .map_flags = 0,  // Set flags to 0
};

// Event structure - must match Go side
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
    
    // Working directory placeholder
    const char *fake_cwd = "/";
    bpf_probe_read_str(&event.cwd, sizeof(event.cwd), fake_cwd);
    
    // Collect command line arguments - enhanced version
    const char **args = (const char **)(ctx->args[1]);
    char cmd_buffer[512] = {0};
    int offset = 0;
    u8 truncated = 0;
    
    // Loop through arguments (with a reasonable upper limit)
    for (int i = 0; i < 32; i++) {
        const char *arg = NULL;
        bpf_probe_read(&arg, sizeof(arg), &args[i]);
        if (!arg) break;  // No more arguments
        
        // Add space between arguments
        if (i > 0 && offset < sizeof(cmd_buffer) - 1) {
            cmd_buffer[offset++] = ' ';
        }
        
        // Read the argument string
        char arg_buf[128];
        bpf_probe_read_str(arg_buf, sizeof(arg_buf), arg);
        
        // Copy to command line buffer
        for (int j = 0; j < sizeof(arg_buf) && arg_buf[j]; j++) {
            if (offset >= sizeof(cmd_buffer) - 1) {
                truncated = 1;
                break;
            }
            cmd_buffer[offset++] = arg_buf[j];
        }
        
        if (truncated) {
            break;
        }
    }
    
    // Copy command line to event
    bpf_probe_read(&event.cmdline, sizeof(event.cmdline), cmd_buffer);
    event.is_truncated = truncated;
    
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
    
    // We can't reliably access ctx->exit_code, so we'll use a placeholder
    event.exit_code = 0;
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}