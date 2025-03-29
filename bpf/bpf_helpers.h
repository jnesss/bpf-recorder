#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#define SEC(NAME) __attribute__((section(NAME), used))

static void* (*bpf_map_lookup_elem)(void* map, const void* key) = (void*) 1;
static int (*bpf_map_update_elem)(void* map, const void* key, const void* value, u64 flags) = (void*) 2;
static int (*bpf_map_delete_elem)(void* map, const void* key) = (void*) 3;
static int (*bpf_probe_read)(void* dst, u32 size, const void* unsafe_ptr) = (void*) 4;
static int (*bpf_probe_read_str)(void *dst, u32 size, const void *unsafe_ptr) = (void*) 45;
static u64 (*bpf_ktime_get_ns)(void) = (void*) 5;
static int (*bpf_trace_printk)(const char* fmt, u32 fmt_size, ...) = (void*) 6;
static u64 (*bpf_get_current_pid_tgid)(void) = (void*) 14;
static int (*bpf_get_current_comm)(void* buf, u32 size_of_buf) = (void*) 16;
static int (*bpf_perf_event_output)(void* ctx, void* map, u64 flags, void* data, u64 size) = (void*) 25;

/* Flags for bpf_perf_event_output */
#define BPF_F_CURRENT_CPU 0xffffffffULL

#endif
