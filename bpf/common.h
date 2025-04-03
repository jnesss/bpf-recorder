#ifndef __COMMON_H
#define __COMMON_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 8192
#define ALLOW_PKT 1
#define ALLOW_SK 1

// Event types
#define EVENT_PROCESS_EXEC 1   // Process execution
#define EVENT_PROCESS_EXIT 2   // Process exit
#define EVENT_NET_CONNECT  3   // Network connect
#define EVENT_NET_ACCEPT   4   // Network accept
#define EVENT_NET_BIND     5   // Network bind
#define EVENT_DNS          6   // DNS query or response
#define EVENT_TLS          7   // TLS handshake events

// DNS operation flags
#define DNS_QUERY    1   // Outbound DNS query
#define DNS_RESPONSE 2   // Inbound DNS response

// TLS operation flags
#define TLS_CLIENT   1   // Client-side TLS handshake
#define TLS_SERVER   2   // Server-side TLS handshake
#define TLS_HANDSHAKE 1  // TLS handshake detected

// DNS constants
#define DNS_MAX_NAME_LEN 128
#define DNS_MAX_LABEL_LEN 63
#define MAX_DNS_SEGMENTS 10

// Enhanced process event structure - matching old structure
struct process_event {
    __u32 event_type;          // Type of event
    __u32 pid;                 // Process ID
    __u64 timestamp;           // Event timestamp
    char comm[TASK_COMM_LEN];  // Process name
    __u32 ppid;                // Parent process ID (if available)
    __u32 uid;                 // User ID
    __u32 gid;                 // Group ID
    __u32 exit_code;           // Exit code (for exit events)    
    char parent_comm[TASK_COMM_LEN]; // Parent process name
    char exe_path[64];               // Executable path
    __u32 flags;                     // Additional flags
};

// Network event structure
struct network_event {
    __u32 event_type;         // Type of event
    __u32 pid;                // Process ID
    __u64 timestamp;          // Event timestamp
    char comm[TASK_COMM_LEN]; // Process name
    __u32 saddr_a;            // Source IP address parts
    __u32 saddr_b;
    __u32 saddr_c;
    __u32 saddr_d;
    __u32 daddr_a;            // Destination IP address parts
    __u32 daddr_b;
    __u32 daddr_c;
    __u32 daddr_d;
    __u16 sport;              // Source port
    __u16 dport;              // Destination port
    __u8  protocol;           // Protocol (TCP/UDP)
};

// Socket info for tracking process info
struct sock_info {
    __u32 pid;
    char comm[TASK_COMM_LEN];
};

// Command line info structure - used in maps, not on stack
struct cmd_line {
    char args[128];           // Command line arguments (reduced size for BPF verifier)
};

// DNS event structure
typedef struct dns_event {
    __u32 event_type;         // Type of event = EVENT_DNS
    __u32 pid;                // Process ID
    __u64 timestamp;          // Event timestamp
    char comm[TASK_COMM_LEN]; // Process name
    __u32 saddr_a;            // Source IP address parts
    __u32 saddr_b;
    __u32 saddr_c;
    __u32 saddr_d;
    __u32 daddr_a;            // Destination IP address parts
    __u32 daddr_b;
    __u32 daddr_c;
    __u32 daddr_d;
    __u16 sport;              // Source port
    __u16 dport;              // Destination port
    __u8  op_flags;           // Operation flags (DNS_QUERY, DNS_RESPONSE)
    __u16 txid;               // DNS transaction ID
    __u16 flags;              // DNS flags
    __u16 question_count;     // Number of questions
    __u16 answer_count;       // Number of answers
    __u8  is_response;        // 1 if response, 0 if query
    __u16 query_type;         // Query type (A=1, AAAA=28, etc)
    char query_name[DNS_MAX_NAME_LEN]; // Query domain name
} dns_event_t;

// TLS event structure
typedef struct tls_event {
    __u32 event_type;         // Type of event = EVENT_TLS
    __u32 pid;                // Process ID
    __u64 timestamp;          // Event timestamp
    char comm[TASK_COMM_LEN]; // Process name
    __u32 saddr_a;            // Source IP address parts
    __u32 saddr_b;
    __u32 saddr_c;
    __u32 saddr_d;
    __u32 daddr_a;            // Destination IP address parts
    __u32 daddr_b;
    __u32 daddr_c;
    __u32 daddr_d;
    __u16 sport;              // Source port
    __u16 dport;              // Destination port
    __u16 tls_version;        // TLS version
    __u8  handshake_type;     // Handshake type
    __u8  cipher_len;         // Length of cipher
    __u16 ciphers[8];         // Cipher suites (simplified)
    char sni[DNS_MAX_NAME_LEN]; // Server Name Indication (hostname)
} tls_event_t;


#endif /* __COMMON_H */
