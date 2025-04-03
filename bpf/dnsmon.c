// bpf/dnsmon.c
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

// DNS protocol constants
#define DNS_PORT 53
#define DNS_HEADER_SIZE 12
#define DNS_MAX_NAME_LEN 128

// Track socket creation via cgroup hook (reuse from netmon.c)
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

static inline int is_dns_packet(void *data, void *data_end, __u16 src_port, __u16 dst_port) {
    // Check if this is a DNS packet (either source or destination port is 53)
    return (src_port == DNS_PORT || dst_port == DNS_PORT);
}

static inline void extract_dns_query(dns_event_t *evt, void *data, void *data_end) {
    // Ensure we can access the DNS header (12 bytes)
    if (data + DNS_HEADER_SIZE > data_end)
        return;
    
    struct dnshdr {
        __u16 id;
        __u16 flags;
        __u16 qdcount;
        __u16 ancount;
        __u16 nscount;
        __u16 arcount;
    } *dns;
    
    dns = (struct dnshdr *)data;
    
    // Fill basic DNS info
    evt->txid = bpf_ntohs(dns->id);
    evt->flags = bpf_ntohs(dns->flags);
    evt->question_count = bpf_ntohs(dns->qdcount);
    evt->answer_count = bpf_ntohs(dns->ancount);
    
    // Determine if this is a query (QR=0) or response (QR=1)
    evt->is_response = (evt->flags & 0x8000) ? 1 : 0;
    
    // Only extract query name for DNS queries (not responses)
    if (evt->question_count > 0) {
        // Point to the start of the query section
        unsigned char *query_start = data + DNS_HEADER_SIZE;
        unsigned char *query_end = data_end;
        
        if (query_start < query_end) {
            // Read DNS name (encoded as length octets followed by data)
            unsigned char *src = query_start;
            unsigned char *dst = evt->query_name;
            int len_remaining = DNS_MAX_NAME_LEN - 1;  // Leave room for null terminator
            unsigned char label_len = 0;
            
            // Check if we can read the first byte
            if (src + 1 > query_end)
                return;
                
            // Get first label length
            label_len = *src;
            src++;
            
            // Process labels
            #pragma unroll
            for (int i = 0; i < MAX_DNS_SEGMENTS; i++) {
                // Check bounds for label_len bytes
                if (src + label_len > query_end || len_remaining <= 0)
                    break;
                    
                // Copy up to label_len bytes
                for (int j = 0; j < DNS_MAX_LABEL_LEN; j++) {
                    if (j >= label_len || len_remaining <= 0)
                        break;
                        
                    if (src + j >= query_end)
                        break;
                        
                    dst[0] = src[j];
                    dst++;
                    len_remaining--;
                }
                
                // Move to next label
                src += label_len;
                
                // Break if we reach end
                if (src >= query_end || len_remaining <= 0)
                    break;
                    
                // Check for end of name (0 length)
                if (*src == 0)
                    break;
                    
                // Add dot separator
                if (len_remaining > 0) {
                    dst[0] = '.';
                    dst++;
                    len_remaining--;
                }
                
                // Get next label length
                label_len = *src;
                src++;
            }
            
            // Null terminate
            if (len_remaining > 0)
                dst[0] = '\0';
        }
    }
    
    // Try to get query type if we have enough data
    unsigned char *query_start = data + DNS_HEADER_SIZE;
    unsigned char *pos = query_start;
    
    // Skip the name part
    while (pos + 1 < data_end) {
        if (*pos == 0) {
            // End of name, next 2 bytes are QTYPE
            pos++;
            if (pos + 2 <= data_end) {
                evt->query_type = (__u16)pos[0] << 8 | pos[1];
            }
            break;
        }
        
        // Handle compression pointers (message compression)
        if ((*pos & 0xC0) == 0xC0) {
            // Compressed name, skip 2 bytes
            pos += 2;
            if (pos + 2 <= data_end) {
                evt->query_type = (__u16)pos[0] << 8 | pos[1];
            }
            break;
        }
        
        // Skip label
        unsigned int len = *pos;
        pos += len + 1;
    }
}

static inline void process_skb_dns(struct __sk_buff *skb, __u8 event_subtype) {
    // Get socket cookie
    __u64 cookie = bpf_get_socket_cookie(skb);
    
    // Look up process info
    struct sock_info *info = bpf_map_lookup_elem(&sock_info, &cookie);
    if (!info) {
        return; // Skip if no process info found
    }
    
    // Now we have the process info, extract connection details from skb
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Extract IP version from skb protocol
    __u16 proto = bpf_ntohs(skb->protocol);
    
    // Parse IPv4 packet
    if (proto == 0x0800) { // ETH_P_IP
        struct iphdr *ip = data;
        if ((void*)(ip + 1) > data_end) {
            return;
        }
        
        // Extract IP addresses
        __be32 src_ip = ip->saddr;
        __be32 dst_ip = ip->daddr;
        
        // We're interested in UDP packets (DNS)
        if (ip->protocol == 17) { // UDP
            struct udphdr *udp = (void*)(ip + 1);
            if ((void*)(udp + 1) > data_end) {
                return;
            }
            
            __u16 src_port = bpf_ntohs(udp->source);
            __u16 dst_port = bpf_ntohs(udp->dest);
            
            // Check if it's a DNS packet
            if (is_dns_packet(data, data_end, src_port, dst_port)) {
                // DNS payload starts after UDP header
                void *dns_data = (void*)(udp + 1);
                
                // Create DNS event
                dns_event_t *evt;
                evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
                if (!evt) {
                    return;
                }
                
                // Initialize event
                __builtin_memset(evt, 0, sizeof(*evt));
                
                // Fill header information
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
                
                // Extract DNS-specific information
                extract_dns_query(evt, dns_data, data_end);
                
                bpf_ringbuf_submit(evt, 0);
            }
        }
    }
}

// Ingress traffic monitoring - reuse from netmon.c but enhance for DNS
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
    process_skb_dns(skb, DNS_RESPONSE);
    return ALLOW_PKT;
}

// Egress traffic monitoring - reuse from netmon.c but enhance for DNS
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
    process_skb_dns(skb, DNS_QUERY);
    return ALLOW_PKT;
}

// TLS/SNI extraction - lightweight approach to extract SNI from Client Hello
static inline void extract_sni(struct __sk_buff *skb, __u8 event_subtype) {
    // Get socket cookie
    __u64 cookie = bpf_get_socket_cookie(skb);
    
    // Look up process info
    struct sock_info *info = bpf_map_lookup_elem(&sock_info, &cookie);
    if (!info) {
        return; // Skip if no process info found
    }
    
    // Now we have the process info, extract connection details from skb
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Extract IP version from skb protocol
    __u16 proto = bpf_ntohs(skb->protocol);
    
    // Parse IPv4 packet
    if (proto == 0x0800) { // ETH_P_IP
        struct iphdr *ip = data;
        if ((void*)(ip + 1) > data_end) {
            return;
        }
        
        // Extract IP addresses
        __be32 src_ip = ip->saddr;
        __be32 dst_ip = ip->daddr;
        
        // We're interested in TCP packets for TLS
        if (ip->protocol == 6) { // TCP
            struct tcphdr *tcp = (void*)(ip + 1);
            if ((void*)(tcp + 1) > data_end) {
                return;
            }
            
            __u16 src_port = bpf_ntohs(tcp->source);
            __u16 dst_port = bpf_ntohs(tcp->dest);
            
            // Simple TLS detection: Check for common HTTPS port (443)
            // This is a simplification - real implementation should check TLS record format
            if (dst_port == 443 || src_port == 443) {
                void *payload = (void*)(tcp + 1);
                
                // Check if we have enough data (TLS record header is 5 bytes)
                if (payload + 5 > data_end) 
                    return;
                
                // Check if this looks like a TLS handshake packet
                unsigned char *tls = payload;
                
                // TLS Record Type 22 = Handshake
                if (tls[0] == 0x16) {
                    // We have a TLS handshake, create an event
                    tls_event_t *evt;
                    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
                    if (!evt) {
                        return;
                    }
                    
                    // Initialize event
                    __builtin_memset(evt, 0, sizeof(*evt));
                    
                    // Fill header information
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
                    
                    // Set TLS version from record (bytes 1-2)
                    if (payload + 5 <= data_end) {
                        evt->tls_version = (__u16)tls[1] << 8 | tls[2];
                    }
                    
                    // Note: Full SNI extraction would require more complex parsing
                    // of the Client Hello message, which is beyond our simple implementation
                    // Just mark that we detected TLS traffic
                    evt->handshake_type = TLS_HANDSHAKE;
                    
                    bpf_ringbuf_submit(evt, 0);
                }
            }
        }
    }
}

// Enhanced egress traffic monitoring for TLS/SNI
SEC("cgroup_skb/egress")
int cgroup_skb_tls_egress(struct __sk_buff *skb) {
    extract_sni(skb, TLS_CLIENT);
    return ALLOW_PKT;
}

char LICENSE[] SEC("license") = "GPL";
