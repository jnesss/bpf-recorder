//go:build ignore

#include "common.h"
#include "bpf_helpers.h"
#include <linux/sched.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 128,
};

// Helper macro for safer kernel structure reading
#define READ_KERN(dst, src) \
    bpf_probe_read(&dst, sizeof(dst), &src)

// Handle process execution with enhanced metadata
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
    struct event event = {0};
    __builtin_memset(&event, 0, sizeof(event)); // clear event
    
    // Get current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Basic process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 1; // EXEC event
    
    // Get parent PID and comm (safely)
    struct task_struct *parent;
    READ_KERN(parent, task->real_parent);
    u32 ppid = 0;
    READ_KERN(ppid, parent->tgid);
    event.ppid = ppid;
    
    char parent_comm[16] = {0};
    bpf_probe_read_str(&parent_comm, sizeof(parent_comm), &parent->comm);
    __builtin_memcpy(&event.parent_comm, parent_comm, sizeof(event.parent_comm));
    
    // Get UID/GID
    struct cred *creds;
    READ_KERN(creds, task->cred);
    u32 uid = 0, gid = 0;
    READ_KERN(uid, creds->uid.val);
    READ_KERN(gid, creds->gid.val);
    event.uid = uid;
    event.gid = gid;
    
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
    
    // Current working directory placeholder
    const char *fake_cwd = "/placeholder";
    bpf_probe_read_str(&event.cwd, sizeof(event.cwd), fake_cwd);
    
    // Output event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Handle process exit - update to match new event structure
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