const KERNEL_FEATURE_MAP_HASH = {
    key: "map:BPF_MAP_TYPE_HASH"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_ARRAY = {
    key: "map:BPF_MAP_TYPE_ARRAY"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_CGROUP_ARRAY = {
    key: "map:BPF_MAP_TYPE_CGROUP_ARRAY"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_LRU_HASH = {
    key: "map:BPF_MAP_TYPE_LRU_HASH"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_LPM_TRIE = {
    key: "map:BPF_MAP_TYPE_LPM_TRIE"
    min_kernel: "4.11"
    source: "https://github.com/torvalds/linux/blob/v4.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_PERCPU_HASH = {
    key: "map:BPF_MAP_TYPE_PERCPU_HASH"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_PERCPU_ARRAY = {
    key: "map:BPF_MAP_TYPE_PERCPU_ARRAY"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_LRU_PERCPU_HASH = {
    key: "map:BPF_MAP_TYPE_LRU_PERCPU_HASH"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
