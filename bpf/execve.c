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
    .value_size = 512,  // Increased to 512 bytes
    .max_entries = 1024,
    .map_flags = 0,
};

// Define a per-CPU array for our command line buffer
struct bpf_map_def SEC("maps") cmdline_buffer = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = 512,  // Increased to 512 bytes
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
    
    // Get the arguments array
    const char **args = (const char **)(ctx->args[1]);
    
    // Use a per-CPU array instead of stack buffer
    u32 zero = 0;
    char *buffer = bpf_map_lookup_elem(&cmdline_buffer, &zero);
    if (!buffer)
        return 0;  // Can't proceed without buffer
    
    // Initialize buffer to zeros
    __builtin_memset(buffer, 0, 512);
    
    // Fixed buffer regions for each argument with expanded sizes
    // Argument allocation:
    // arg0: 0-95    (96 bytes)
    // arg1: 96-175  (80 bytes)
    // arg2: 176-255 (80 bytes)
    // arg3: 256-319 (64 bytes)
    // arg4: 320-383 (64 bytes)
    // arg5: 384-431 (48 bytes)
    // arg6: 432-479 (48 bytes)
    // arg7: 480-511 (32 bytes)
    
    // Arg 0 (program name) - 96 bytes
    const char *arg0 = NULL;
    bpf_probe_read(&arg0, sizeof(arg0), &args[0]);
    if (arg0) {
        bpf_probe_read_str(buffer, 96, arg0);
    }
    
    // Arg 1 - starts at offset 96, max 80 bytes
    const char *arg1 = NULL;
    bpf_probe_read(&arg1, sizeof(arg1), &args[1]);
    if (arg1) {
        // Add a space if we have content in buffer
        if (buffer[0] != 0) {
            buffer[95] = ' ';
        }
        bpf_probe_read_str(buffer + 96, 80, arg1);
    }
    
    // Arg 2 - starts at offset 176, max 80 bytes
    const char *arg2 = NULL;
    bpf_probe_read(&arg2, sizeof(arg2), &args[2]);
    if (arg2) {
        // Add a space if we have content before
        if (buffer[96] != 0) {
            buffer[175] = ' ';
        }
        bpf_probe_read_str(buffer + 176, 80, arg2);
    }
    
    // Arg 3 - starts at offset 256, max 64 bytes
    const char *arg3 = NULL;
    bpf_probe_read(&arg3, sizeof(arg3), &args[3]);
    if (arg3) {
        if (buffer[176] != 0) {
            buffer[255] = ' ';
        }
        bpf_probe_read_str(buffer + 256, 64, arg3);
    }
    
    // Arg 4 - starts at offset 320, max 64 bytes
    const char *arg4 = NULL;
    bpf_probe_read(&arg4, sizeof(arg4), &args[4]);
    if (arg4) {
        if (buffer[256] != 0) {
            buffer[319] = ' ';
        }
        bpf_probe_read_str(buffer + 320, 64, arg4);
    }
    
    // Arg 5 - starts at offset 384, max 48 bytes
    const char *arg5 = NULL;
    bpf_probe_read(&arg5, sizeof(arg5), &args[5]);
    if (arg5) {
        if (buffer[320] != 0) {
            buffer[383] = ' ';
        }
        bpf_probe_read_str(buffer + 384, 48, arg5);
    }
    
    // Arg 6 - starts at offset 432, max 48 bytes
    const char *arg6 = NULL;
    bpf_probe_read(&arg6, sizeof(arg6), &args[6]);
    if (arg6) {
        if (buffer[384] != 0) {
            buffer[431] = ' ';
        }
        bpf_probe_read_str(buffer + 432, 48, arg6);
    }
    
    // Arg 7 - starts at offset 480, max 32 bytes
    const char *arg7 = NULL;
    bpf_probe_read(&arg7, sizeof(arg7), &args[7]);
    if (arg7) {
        if (buffer[432] != 0) {
            buffer[479] = ' ';
        }
        bpf_probe_read_str(buffer + 480, 32, arg7);
    }
    
    // Make sure it's null-terminated
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