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

// Map for overflow command lines
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 512);
    __uint(max_entries, 1);
} cmdline_overflow SEC(".maps");

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
    
    // Collect command line arguments directly into event structure
    const char **args = (const char **)(ctx->args[1]);
    int offset = 0;
    u8 truncated = 0;
    
    // Get map for overflow if needed
    u32 zero = 0;
    char *overflow_buf = NULL;
    
    // Loop through arguments to build command line
    for (int i = 0; i < 32; i++) {
        const char *arg = NULL;
        bpf_probe_read(&arg, sizeof(arg), &args[i]);
        if (!arg) break;  // No more arguments
        
        // Add space between arguments
        if (i > 0 && offset < sizeof(event.cmdline) - 1) {
            event.cmdline[offset++] = ' ';
        } else if (i > 0 && truncated) {
            // We're in overflow mode
            if (!overflow_buf) {
                overflow_buf = bpf_map_lookup_elem(&cmdline_overflow, &zero);
                if (!overflow_buf) {
                    break; // Can't use overflow buffer
                }
            }
            overflow_buf[offset++] = ' ';
            if (offset >= 511) {
                break; // Out of space even in overflow buffer
            }
        }
        
        // Read the argument string
        char arg_buf[64];
        bpf_probe_read_str(arg_buf, sizeof(arg_buf), arg);
        
        // Copy to appropriate buffer
        for (int j = 0; j < sizeof(arg_buf) && arg_buf[j]; j++) {
            if (!truncated && offset < sizeof(event.cmdline) - 1) {
                // Still using event structure buffer
                event.cmdline[offset++] = arg_buf[j];
            } else {
                // Need to use overflow buffer
                if (!truncated) {
                    // First time hitting truncation
                    truncated = 1;
                    // Get overflow buffer
                    overflow_buf = bpf_map_lookup_elem(&cmdline_overflow, &zero);
                    if (!overflow_buf) {
                        break; // Can't use overflow buffer
                    }
                    
                    // Copy what we have so far to overflow buffer
                    for (int k = 0; k < offset; k++) {
                        overflow_buf[k] = event.cmdline[k];
                    }
                }
                
                if (offset < 511) {
                    overflow_buf[offset++] = arg_buf[j];
                } else {
                    break; // Out of space even in overflow buffer
                }
            }
        }
        
        if (truncated && !overflow_buf) {
            break; // Can't use overflow buffer
        }
        
        if (truncated && offset >= 511) {
            break; // Out of space even in overflow buffer
        }
    }
    
    // Ensure null termination
    if (!truncated) {
        if (offset < sizeof(event.cmdline)) {
            event.cmdline[offset] = '\0';
        } else {
            event.cmdline[sizeof(event.cmdline) - 1] = '\0';
        }
    } else if (overflow_buf) {
        if (offset < 512) {
            overflow_buf[offset] = '\0';
        } else {
            overflow_buf[511] = '\0';
        }
    }
    
    // Set command line length and truncation flag
    event.cmdline_len = offset;
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
    
    event.exit_code = 0;
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}