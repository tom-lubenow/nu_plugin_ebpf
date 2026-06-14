const KERNEL_FEATURE_PROG_ITER = {
    key: "program:BPF_PROG_TYPE_TRACING-iter"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_ITER_TARGET_TASK = {
    key: "iter-target:task"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_TASK_FILE = {
    key: "iter-target:task_file"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_TASK_VMA = {
    key: "iter-target:task_vma"
    min_kernel: "5.12"
    source: "https://github.com/torvalds/linux/blob/v5.12/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_MAP = {
    key: "iter-target:bpf_map"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/map_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_CGROUP = {
    key: "iter-target:cgroup"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/cgroup_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_MAP_ELEM = {
    key: "iter-target:bpf_map_elem"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/map_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_SK_STORAGE_MAP = {
    key: "iter-target:bpf_sk_storage_map"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/core/bpf_sk_storage.c"
}
const KERNEL_FEATURE_ITER_TARGET_SOCKMAP = {
    key: "iter-target:sockmap"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/net/core/sock_map.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_PROG = {
    key: "iter-target:bpf_prog"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/prog_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_LINK = {
    key: "iter-target:bpf_link"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/link_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_KSYM = {
    key: "iter-target:ksym"
    min_kernel: "6.0"
    source: "https://github.com/torvalds/linux/blob/v6.0/kernel/kallsyms.c"
}
const KERNEL_FEATURE_ITER_TARGET_KMEM_CACHE = {
    key: "iter-target:kmem_cache"
    min_kernel: "6.13"
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/kmem_cache_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_DMABUF = {
    key: "iter-target:dmabuf"
    min_kernel: "6.16"
    source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/dmabuf_iter.c"
}
