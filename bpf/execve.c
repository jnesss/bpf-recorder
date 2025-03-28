//go:build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Smaller buffer sizes
#define ARGSIZE  64
#define MAXARG   4

struct event {
    u32 pid;         // Process ID
    u32 _pad0;       // padding for 64-bit alignment
    u64 timestamp;   // Timestamp in nanoseconds
    char comm[16];   // Process name
    char filename[ARGSIZE]; // Executable path
    int event_type;  // 1 = exec, 2 = exit
    int exit_code;   // Exit code for exit events
} __attribute__((packed)); // ensure no extra padding is added;

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 128,
};

// Handle process execution
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
    struct event event = {0};
    __builtin_memset(&event, 0, sizeof(event)); // clear event
    
    // Basic process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 1; // EXEC event
    
    // Get filename (executable path)
    const char* filename = (const char*)ctx->args[0];

    // Make sure we null-terminate properly
    int i;
    for (i=0; i < sizeof(event.filename) - 1 && i < ARGSIZE; i++) {
        char c;
        bpf_probe_read(&c, 1, filename + i);
        event.filename[i] = c;
        if (c == 0)
            break;
    }
    event.filename[i] = 0; // null terminate
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Handle process exit - simplified version
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template* ctx) {
    struct event event = {0};
    
    // Basic process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 2; // EXIT event
    
    // Get exit code
    event.exit_code = ctx->exit_code;
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
