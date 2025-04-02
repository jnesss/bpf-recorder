// bpf/netmon.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

// Ringbuffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Map to track socket -> PID mapping (LRU to handle high volume)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct sock_info);
} sock_info SEC(".maps");

// Track socket creation via cgroup hook
SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *sk) {
    struct sock_info info = {};
    
    // Get process info
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    
    // Store in map using socket cookie as key
    __u64 cookie = bpf_get_socket_cookie((void *)sk);
    if (cookie) {
        bpf_map_update_elem(&sock_info, &cookie, &info, BPF_ANY);
    }
    
    return ALLOW_SK;
}

// Process CGroup skb to extract connection info
static inline void process_cgroup_skb(struct __sk_buff *skb, __u8 event_subtype) {
    // Get socket cookie
    __u64 cookie = bpf_get_socket_cookie(skb);
    
    // Look up process info
    struct sock_info *info = bpf_map_lookup_elem(&sock_info, &cookie);
    if (!info) {
        return; // Skip if no process info found
    }
    
    // Now we have the process info, extract connection details from skb
    struct network_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }
    
    // Initialize event
    __builtin_memset(evt, 0, sizeof(*evt));
    
    // Fill header information
    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = info->pid;
    evt->event_type = event_subtype;
    __builtin_memcpy(&evt->comm, info->comm, sizeof(evt->comm));
    
    // Get IP version from skb protocol
    __u16 proto = bpf_ntohs(skb->protocol);
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse IPv4 packet
    if (proto == 0x0800) { // ETH_P_IP
        struct iphdr *ip = data;
        if ((void*)(ip + 1) > data_end) {
            bpf_ringbuf_discard(evt, 0);
            return;
        }
        
        // Extract IP addresses
        __be32 src_ip = ip->saddr;
        __be32 dst_ip = ip->daddr;
        
        // Extract ports based on protocol
        __u8 ip_proto = ip->protocol;
        __u16 src_port = 0;
        __u16 dst_port = 0;
        
        if (ip_proto == 6) { // TCP
            struct tcphdr *tcp = (void*)(ip + 1);
            if ((void*)(tcp + 1) > data_end) {
                bpf_ringbuf_discard(evt, 0);
                return;
            }
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
            evt->protocol = 6; // TCP
        } else if (ip_proto == 17) { // UDP
            struct udphdr *udp = (void*)(ip + 1);
            if ((void*)(udp + 1) > data_end) {
                bpf_ringbuf_discard(evt, 0);
                return;
            }
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
            evt->protocol = 17; // UDP
        }
        
        // Fill in connection details
        evt->saddr_a = (src_ip) & 0xFF;
        evt->saddr_b = (src_ip >> 8) & 0xFF;
        evt->saddr_c = (src_ip >> 16) & 0xFF;
        evt->saddr_d = (src_ip >> 24) & 0xFF;
        evt->daddr_a = (dst_ip) & 0xFF;
        evt->daddr_b = (dst_ip >> 8) & 0xFF;
        evt->daddr_c = (dst_ip >> 16) & 0xFF;
        evt->daddr_d = (dst_ip >> 24) & 0xFF;
        evt->sport = src_port;
        evt->dport = dst_port;
        
        bpf_ringbuf_submit(evt, 0);
    } else {
        // Skip non-IPv4 packets for simplicity
        bpf_ringbuf_discard(evt, 0);
    }
}

// Ingress traffic monitoring
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
    process_cgroup_skb(skb, EVENT_NET_ACCEPT);
    return ALLOW_PKT;
}

// Egress traffic monitoring
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
    process_cgroup_skb(skb, EVENT_NET_CONNECT);
    return ALLOW_PKT;
}

// Track bind events via syscall
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    
    // Initialize event
    __builtin_memset(evt, 0, sizeof(*evt));
    
    // Fill header information
    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->event_type = EVENT_NET_BIND;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
