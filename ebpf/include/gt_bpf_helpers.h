/* Minimal helper declarations for GhostTrace. No libbpf headers required. */
#ifndef GT_BPF_HELPERS_H
#define GT_BPF_HELPERS_H
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static __u64 (*const bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*const bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*const bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static long (*const bpf_get_current_comm)(void *, __u32) = (void *)BPF_FUNC_get_current_comm;
static void *(*const bpf_map_lookup_elem)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static void *(*const bpf_ringbuf_reserve)(void *, __u64, __u64) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*const bpf_ringbuf_submit)(void *, __u64) = (void *)BPF_FUNC_ringbuf_submit;
#endif
