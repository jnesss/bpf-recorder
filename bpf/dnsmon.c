// bpf/dnsmon.c - Version 3: Adding basic TLS detection
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

// Map to track socket -> PID mapping
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct sock_info);
} sock_info SEC(".maps");

// Protocol constants
#define DNS_PORT 53
#define HTTPS_PORT 443
#define DNS_HEADER_SIZE 12
#define DNS_MAX_NAME_LEN 128
#define MAX_LABEL_SIZE 15  // Keep this small for verifier

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

static inline void extract_multilabel_name_v1(dns_event_t *evt, void *data, void *data_end) {
    unsigned char *query_start = (unsigned char *)data + DNS_HEADER_SIZE;
    __builtin_memset(evt->query_name, 0, DNS_MAX_NAME_LEN);
    
    if ((void *)(query_start + 1) > data_end) return;
    
    int pos = 0;
    
    // First label
    unsigned char len1 = *query_start;
    if (len1 == 0 || len1 > 63 || (void *)(query_start + 1 + len1) > data_end) return;
    
    // Copy only 15 chars max per label to reduce instruction count
    for (int i = 0; i < len1 && i < 15 && pos < DNS_MAX_NAME_LEN - 1; i++) {
        if ((void *)(query_start + 1 + i) >= data_end) break;
        evt->query_name[pos++] = query_start[1 + i];
    }
    
    // Second label
    unsigned char *next = query_start + 1 + len1;
    if ((void *)(next + 1) > data_end) goto done;
    unsigned char len2 = *next;
    if (len2 == 0 || (len2 & 0xC0) == 0xC0) goto done;
    
    if (pos < DNS_MAX_NAME_LEN - 1) evt->query_name[pos++] = '.';
    if ((void *)(next + 1 + len2) > data_end) goto done;
    
    for (int i = 0; i < len2 && i < 15 && pos < DNS_MAX_NAME_LEN - 1; i++) {
        if ((void *)(next + 1 + i) >= data_end) break;
        evt->query_name[pos++] = next[1 + i];
    }
    
    // Third label
    next = next + 1 + len2;
    if ((void *)(next + 1) > data_end) goto done;
    unsigned char len3 = *next;
    if (len3 == 0 || (len3 & 0xC0) == 0xC0) goto done;
    
    if (pos < DNS_MAX_NAME_LEN - 1) evt->query_name[pos++] = '.';
    if ((void *)(next + 1 + len3) > data_end) goto done;
    
    for (int i = 0; i < len3 && i < 15 && pos < DNS_MAX_NAME_LEN - 1; i++) {
        if ((void *)(next + 1 + i) >= data_end) break;
        evt->query_name[pos++] = next[1 + i];
    }

done:
    // Null terminate
    if (pos < DNS_MAX_NAME_LEN) evt->query_name[pos] = '\0';
}

// Parse DNS packet with basic header parsing and simple name extraction
static inline void process_skb_dns(struct __sk_buff *skb, __u8 event_subtype) {
    // Get socket cookie
    __u64 cookie = bpf_get_socket_cookie(skb);
    
    // Look up process info
    struct sock_info *info = bpf_map_lookup_elem(&sock_info, &cookie);
    if (!info) {
        return; // Skip if no process info found
    }
    
    // Get packet data
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Check if we have an IPv4 packet
    if (bpf_ntohs(skb->protocol) != 0x0800) {
        return;
    }
    
    // Verify we have enough data for IP header
    struct iphdr *ip = data;
    if ((void*)(ip + 1) > data_end) {
        return;
    }
    
    // Verify IP header length
    if (ip->ihl < 5) {
        return;
    }
    
    // Calculate IP header size with bounds check
    __u32 ip_header_size = ip->ihl * 4;
    if ((void*)data + ip_header_size > data_end) {
        return;
    }
    
    // Extract IP addresses
    __be32 src_ip = ip->saddr;
    __be32 dst_ip = ip->daddr;
    
    // Process UDP (DNS) packets
    if (ip->protocol == 17) { // UDP
        struct udphdr *udp = (void*)data + ip_header_size;
        if ((void*)(udp + 1) > data_end) {
            return;
        }
        
        // Check if it's a DNS packet (port 53)
        __u16 src_port = bpf_ntohs(udp->source);
        __u16 dst_port = bpf_ntohs(udp->dest);
        
        if (src_port != DNS_PORT && dst_port != DNS_PORT) {
            return;
        }
        
        // Calculate UDP header size and check DNS header bounds
        __u32 udp_header_size = 8;
        void *dns_data = (void*)udp + udp_header_size;
        
        // Ensure we can read the DNS header
        if (dns_data + DNS_HEADER_SIZE > data_end) {
            return;
        }
        
        // Define DNS header structure
        struct dnshdr {
            __u16 id;
            __u16 flags;
            __u16 qdcount;
            __u16 ancount;
            __u16 nscount;
            __u16 arcount;
        } *dns = dns_data;
        
        // It's a DNS packet - create an event
        dns_event_t *evt;
        evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) {
            return;
        }
        
        // Clear the event structure
        __builtin_memset(evt, 0, sizeof(*evt));
        
        // Fill in basic information
        evt->timestamp = bpf_ktime_get_ns();
        evt->pid = info->pid;
        evt->event_type = EVENT_DNS;
        evt->op_flags = event_subtype;
        __builtin_memcpy(&evt->comm, info->comm, sizeof(evt->comm));
        
        // Fill network details
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
        
        // Extract DNS header fields
        evt->txid = bpf_ntohs(dns->id);
        evt->flags = bpf_ntohs(dns->flags);
        evt->question_count = bpf_ntohs(dns->qdcount);
        evt->answer_count = bpf_ntohs(dns->ancount);
        evt->is_response = (evt->flags & 0x8000) ? 1 : 0;
        
        // Only extract query name for queries with at least one question
        if (evt->question_count > 0 && !evt->is_response) {
	    extract_multilabel_name_v1(evt, dns_data, data_end);
        }
        
        // Submit the event
        bpf_ringbuf_submit(evt, 0);
    } 
    // Process TCP (TLS) packets 
    else if (ip->protocol == 6) { // TCP
        struct tcphdr *tcp = (void*)data + ip_header_size;
        if ((void*)(tcp + 1) > data_end) {
            return;
        }
        
        __u16 src_port = bpf_ntohs(tcp->source);
        __u16 dst_port = bpf_ntohs(tcp->dest);
        
        // Check if it's an HTTPS packet (port 443)
        if (src_port != HTTPS_PORT && dst_port != HTTPS_PORT) {
            return;
        }
        
        // Calculate TCP header size 
        __u8 tcp_header_len = (tcp->doff) << 2;
        if (tcp_header_len < 20) {
            return;  // Invalid TCP header
        }
        
        // Check if TCP header fits in packet
        if ((void*)tcp + tcp_header_len > data_end) {
            return;
        }
        
        // Check for TLS handshake (record type 22)
        void *payload = (void*)tcp + tcp_header_len;
        
        // Make sure we have enough data for basic TLS header (5 bytes)
        if ((void*)payload + 5 > data_end) {
            return;
        }
        
        unsigned char *tls = payload;
        
        // Check for TLS handshake (content type 22)
        if (tls[0] != 0x16) {
            return;
        }
        
        // Create TLS event
        tls_event_t *evt;
        evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) {
            return;
        }
        
        // Clear the event structure
        __builtin_memset(evt, 0, sizeof(*evt));
        
        // Fill in basic information
        evt->timestamp = bpf_ktime_get_ns();
        evt->pid = info->pid;
        evt->event_type = EVENT_TLS;
        __builtin_memcpy(&evt->comm, info->comm, sizeof(evt->comm));
        
        // Fill network details
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
        
        // Extract TLS version with bounds check
        if ((void*)payload + 3 <= data_end) {
            evt->tls_version = (__u16)tls[1] << 8 | tls[2];
        }
        
        // Mark as TLS handshake
        evt->handshake_type = TLS_HANDSHAKE;
        
        // Submit the event
        bpf_ringbuf_submit(evt, 0);
    }
}

// Ingress traffic monitoring
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
    process_skb_dns(skb, DNS_RESPONSE);
    return ALLOW_PKT;
}

// Egress traffic monitoring
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
    process_skb_dns(skb, DNS_QUERY);
    return ALLOW_PKT;
}

char LICENSE[] SEC("license") = "GPL";