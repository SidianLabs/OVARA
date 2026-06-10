// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// ovara_interceptor.c — eBPF syscall interceptor for Ovara runtime gateway
//
// Monitors execve, openat, and tcp_connect syscalls via tracepoints/kprobes.
// Events are pushed through a ring buffer for userspace consumption.
// Policy state is maintained in BPF hash maps (allow/deny per agent).
//
// Build: make -C security/ebpf/
// Load:  bpftool prog load security/ebpf/ovara_interceptor.o /sys/fs/bpf/ovara_interceptor

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define MAX_COMM_LEN  16
#define MAX_PATH_LEN  256
#define MAX_AGENTS    64
#define MAX_ENTRIES   1024
#define TASK_COMM_LEN 16

// Event types pushed through the ring buffer
enum event_type {
    EVENT_EXECVE  = 0,
    EVENT_OPENAT  = 1,
    EVENT_CONNECT = 2,
};

// ---------------------------------------------------------------------------
// Event structs — common header + type-specific payload
// ---------------------------------------------------------------------------

struct event_header {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __s32 event_type;
    char  comm[TASK_COMM_LEN];
};

struct execve_event {
    struct event_header hdr;
    char  filename[MAX_PATH_LEN];
    __u32 nargs;
};

struct open_event {
    struct event_header hdr;
    char  filename[MAX_PATH_LEN];
    __s32 flags;
    __s32 mode;
};

struct connect_event {
    struct event_header hdr;
    __u32 daddr;
    __u16 dport;
    __u16 sport;
    __u32 protocol;
};

// Ring buffer event envelope — wraps any event type
struct ringbuf_event {
    __u32 event_type;
    union {
        struct execve_event  exec;
        struct open_event    open;
        struct connect_event conn;
    } u;
};

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

// Ring buffer for pushing events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1 MB ring buffer
} events SEC(".maps");

// Per-agent execve allow list: key = agent_id (u32), value = 1 (allowed)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_ENTRIES);
} execve_allow SEC(".maps");

// Per-agent execve deny list
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_ENTRIES);
} execve_deny SEC(".maps");

// Per-agent openat allow list (filename hash)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_ENTRIES);
} openat_allow SEC(".maps");

// Per-agent openat deny list (filename hash)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_ENTRIES);
} openat_deny SEC(".maps");

// Per-agent connect allow list (IP as key)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_ENTRIES);
} connect_allow SEC(".maps");

// Per-agent connect deny list (IP as key)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_ENTRIES);
} connect_deny SEC(".maps");

// ---------------------------------------------------------------------------
// .rodata configuration constants
// ---------------------------------------------------------------------------

__u32 global_agent_id SEC(".rodata") = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline void *ringbuf_reserve(__u64 size) {
    return bpf_ringbuf_reserve(&events, size, 0);
}

static __always_inline void ringbuf_submit(void *p) {
    bpf_ringbuf_submit(p, 0);
}

static __always_inline __u32 get_agent_id(void) {
    // Default to global agent; per-process agent mapping can be added via
    // a PID-to-agent map updated from userspace.
    return global_agent_id;
}

// ---------------------------------------------------------------------------
// execve tracepoint handler
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 uid = bpf_get_current_uid_gid();
    __u32 agent_id = get_agent_id();

    // Check deny list — if agent_id is in deny map, skip (could block here
    // but we audit all events; blocking is done by returning -EPERM from
    // a security hook or by userspace policy enforcement).
    __u8 *denied = bpf_map_lookup_elem(&execve_deny, &agent_id);
    if (denied) {
        // Still log the event for audit trail
    }

    struct ringbuf_event *evt = ringbuf_reserve(sizeof(struct ringbuf_event));
    if (!evt)
        return 0;

    evt->event_type = EVENT_EXECVE;
    evt->u.exec.hdr.timestamp_ns = bpf_ktime_get_ns();
    evt->u.exec.hdr.pid = pid;
    evt->u.exec.hdr.tid = tid;
    evt->u.exec.hdr.uid = uid;
    evt->u.exec.hdr.event_type = EVENT_EXECVE;
    bpf_get_current_comm(&evt->u.exec.hdr.comm, sizeof(evt->u.exec.hdr.comm));

    // Read filename from syscall argument (arg0 = filename pointer)
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&evt->u.exec.filename, sizeof(evt->u.exec.filename), filename);

    evt->u.exec.nargs = 0;

    ringbuf_submit(evt);
    return 0;
}

// ---------------------------------------------------------------------------
// openat tracepoint handler
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 uid = bpf_get_current_uid_gid();

    struct ringbuf_event *evt = ringbuf_reserve(sizeof(struct ringbuf_event));
    if (!evt)
        return 0;

    evt->event_type = EVENT_OPENAT;
    evt->u.open.hdr.timestamp_ns = bpf_ktime_get_ns();
    evt->u.open.hdr.pid = pid;
    evt->u.open.hdr.tid = tid;
    evt->u.open.hdr.uid = uid;
    evt->u.open.hdr.event_type = EVENT_OPENAT;
    bpf_get_current_comm(&evt->u.open.hdr.comm, sizeof(evt->u.open.hdr.comm));

    // arg0 = dirfd, arg1 = filename, arg2 = flags, arg3 = mode
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->u.open.filename, sizeof(evt->u.open.filename), filename);
    evt->u.open.flags = (__s32)ctx->args[2];
    evt->u.open.mode = (__s32)ctx->args[3];

    ringbuf_submit(evt);
    return 0;
}

// ---------------------------------------------------------------------------
// tcp_connect kprobe handler
// ---------------------------------------------------------------------------

// Minimal inet_sock layout for CO-RE (kernel >= 5.15 has full BTF)
struct ov_inet_sock {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

SEC("kprobe/tcp_v4_connect")
int handle_tcp_connect(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 uid = bpf_get_current_uid_gid();

    // arg0 = struct sock *sk
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    struct ringbuf_event *evt = ringbuf_reserve(sizeof(struct ringbuf_event));
    if (!evt)
        return 0;

    evt->event_type = EVENT_CONNECT;
    evt->u.conn.hdr.timestamp_ns = bpf_ktime_get_ns();
    evt->u.conn.hdr.pid = pid;
    evt->u.conn.hdr.tid = tid;
    evt->u.conn.hdr.uid = uid;
    evt->u.conn.hdr.event_type = EVENT_CONNECT;
    bpf_get_current_comm(&evt->u.conn.hdr.comm, sizeof(evt->u.conn.hdr.comm));

    // Read inet_sock fields via BPF_CORE_READ
    struct ov_inet_sock isk = {};
    BPF_CORE_READ_INTO(&isk.saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&isk.daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&isk.sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&isk.dport, sk, __sk_common.skc_dport);

    evt->u.conn.daddr = isk.daddr;
    evt->u.conn.sport = isk.sport;
    evt->u.conn.dport = __bpf_ntohs(isk.dport);
    evt->u.conn.protocol = IPPROTO_TCP;

    ringbuf_submit(evt);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
