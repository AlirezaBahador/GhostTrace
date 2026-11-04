// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <linux/types.h>
#include "gt_bpf_helpers.h"

/* Wire format v1: 48 bytes, native little-endian, no C pointer fields.
 * Changes MUST be coordinated with internal/decoder/process.go.
 */
struct gt_process_event {
    __u64 monotonic_ns;  /* bpf_ktime_get_ns: NOT Unix epoch */
    __u32 pid;           /* thread group ID */
    __u32 tid;           /* thread ID */
    __u32 uid;
    __u32 gid;
    __u32 event_type;    /* 1 exec; 2 thread-group leader exit */
    __u32 reserved;
    char comm[16];
};
_Static_assert(sizeof(struct gt_process_event) == 48, "wire format must remain 48 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* bounded: 1 MiB */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drops SEC(".maps");

static __attribute__((always_inline)) void record_drop(void)
{
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&ringbuf_drops, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __attribute__((always_inline)) int emit(__u32 kind)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    /* sched_process_exit runs for all tasks; only emit leader exits.
     * Leader exit is NOT always equivalent to complete group termination.
     */
    if (kind == 2 && tid != pid)
        return 0;

    struct gt_process_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->monotonic_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->event_type = kind;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx)
{
    (void)ctx;
    return emit(1);
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx)
{
    (void)ctx;
    return emit(2);
}

char LICENSE[] SEC("license") = "Apache-2.0";
