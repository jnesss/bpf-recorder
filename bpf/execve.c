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
    .value_size = 1024,  // Increased to 1024 bytes
    .max_entries = 1024,
    .map_flags = 0,
};

// Define a per-CPU array for our command line buffer
struct bpf_map_def SEC("maps") cmdline_buffer = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = 1024,  // Increased to 1024 bytes
    .max_entries = 1,
    .map_flags = 0,
};

// Handle process execution with enhanced metadata
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
    struct process_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = EVENT_EXEC; // EXEC event
    
    // Basic process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
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
    
    // Get filename (executable path) from usermode as fallback
    const char* filename = (const char*)ctx->args[0];
    bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);

    // Add a simple log for the fallback path
    bpf_printk("Fallback path: %s", event.filename);
    
    // Set default flags
    event.flags = 0;

    // Check if task has a valid exe_file in kernel
    void *mm = NULL;
    bpf_probe_read(&mm, sizeof(mm), task + 2336); // kernel 6.1 mm offset

    if (mm) {
        void *exe_file = NULL;
        bpf_probe_read(&exe_file, sizeof(exe_file), mm + 880); // kernel 6.1 exe_file offset
    
        if (exe_file) {
            // Process has a valid executable file
            // Set bit 0 of flags to indicate this
            event.flags |= 1;
        }
    }

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
    __builtin_memset(buffer, 0, 1024);
    
    // Fixed buffer regions for each argument with doubled sizes
    // Argument allocation:
    // arg0: 0-191   (192 bytes)
    // arg1: 192-351 (160 bytes)
    // arg2: 352-511 (160 bytes)
    // arg3: 512-639 (128 bytes)
    // arg4: 640-767 (128 bytes)
    // arg5: 768-863 (96 bytes)
    // arg6: 864-959 (96 bytes)
    // arg7: 960-1023 (64 bytes)
    
    // Arg 0 (program name) - 192 bytes
    const char *arg0 = NULL;
    bpf_probe_read(&arg0, sizeof(arg0), &args[0]);
    if (arg0) {
        bpf_probe_read_str(buffer, 192, arg0);
    }

    // Arg 1 - starts at offset 192, max 160 bytes
    const char *arg1 = NULL;
    bpf_probe_read(&arg1, sizeof(arg1), &args[1]);
    if (arg1) {
        // Add a space only if we have content in buffer AND it's not a null character
        if (buffer[0] != 0) {
            buffer[191] = ' ';
        }
        bpf_probe_read_str(buffer + 192, 160, arg1);
    }

    // Arg 2 - starts at offset 352, max 160 bytes
    const char *arg2 = NULL;
    bpf_probe_read(&arg2, sizeof(arg2), &args[2]);
    if (arg2) {
        // Add a space only if we have content before
        if (buffer[192] != 0) {
            buffer[351] = ' ';
        }
        bpf_probe_read_str(buffer + 352, 160, arg2);
    }

    // Arg 3 - starts at offset 512, max 128 bytes
    const char *arg3 = NULL;
    bpf_probe_read(&arg3, sizeof(arg3), &args[3]);
    if (arg3) {
        if (buffer[352] != 0) {
            buffer[511] = ' ';
        }
        bpf_probe_read_str(buffer + 512, 128, arg3);
    }

    // Arg 4 - starts at offset 640, max 128 bytes
    const char *arg4 = NULL;
    bpf_probe_read(&arg4, sizeof(arg4), &args[4]);
    if (arg4) {
        if (buffer[512] != 0) {
            buffer[639] = ' ';
        }
        bpf_probe_read_str(buffer + 640, 128, arg4);
    }

    // Arg 5 - starts at offset 768, max 96 bytes
    const char *arg5 = NULL;
    bpf_probe_read(&arg5, sizeof(arg5), &args[5]);
    if (arg5) {
        if (buffer[640] != 0) {
            buffer[767] = ' ';
        }
        bpf_probe_read_str(buffer + 768, 96, arg5);
    }

    // Arg 6 - starts at offset 864, max 96 bytes
    const char *arg6 = NULL;
    bpf_probe_read(&arg6, sizeof(arg6), &args[6]);
    if (arg6) {
        if (buffer[768] != 0) {
            buffer[863] = ' ';
        }
        bpf_probe_read_str(buffer + 864, 96, arg6);
    }

    // Arg 7 - starts at offset 960, max 64 bytes
    const char *arg7 = NULL;
    bpf_probe_read(&arg7, sizeof(arg7), &args[7]);
    if (arg7) {
        if (buffer[864] != 0) {
            buffer[959] = ' ';
        }
        bpf_probe_read_str(buffer + 960, 64, arg7);
    }

    // Make sure it's null-terminated
    buffer[1023] = '\0';
    
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
    struct process_event event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = EVENT_EXIT; // EXIT event
    
    // Basic process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.exit_code = 0;
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}