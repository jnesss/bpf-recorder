//go:build ignore

#include "amazon_linux_2023_kernel_6_1_vmlinux.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 128,
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
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Get parent PID using CO-RE macro
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        event.ppid = BPF_CORE_READ(parent, tgid);
        BPF_CORE_READ_STR_INTO(&event.parent_comm, parent, comm);
    }
    
    // Get UID/GID using helper function - more reliable than struct access
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid & 0xffffffff;
    event.gid = uid_gid >> 32;
    
    // Get filename (executable path)
    const char* filename = (const char*)ctx->args[0];
    bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);
    
    // Get command line arguments (simplified - just first arg)
    const char **args = (const char **)(ctx->args[1]);
    const char *arg = NULL;
    bpf_probe_read(&arg, sizeof(arg), &args[1]); // args[0] is program name
    if (arg) {
        bpf_probe_read_str(&event.args, sizeof(event.args), arg);
    }
    
    // Working directory placeholder - this is harder to get reliably
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
    
    // Get exit code
    event.exit_code = ctx->exit_code;
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}