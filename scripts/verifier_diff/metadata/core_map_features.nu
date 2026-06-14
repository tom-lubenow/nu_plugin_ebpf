const KERNEL_FEATURE_MAP_PERF_EVENT_ARRAY = {
    key: "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
    min_kernel: "4.3"
    source: "https://github.com/torvalds/linux/blob/v4.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_STACK_TRACE = {
    key: "map:BPF_MAP_TYPE_STACK_TRACE"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_ARRAY_OF_MAPS = {
    key: "map:BPF_MAP_TYPE_ARRAY_OF_MAPS"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_HASH_OF_MAPS = {
    key: "map:BPF_MAP_TYPE_HASH_OF_MAPS"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_QUEUE = {
    key: "map:BPF_MAP_TYPE_QUEUE"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_STACK = {
    key: "map:BPF_MAP_TYPE_STACK"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_BLOOM_FILTER = {
    key: "map:BPF_MAP_TYPE_BLOOM_FILTER"
    min_kernel: "5.16"
    source: "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_RINGBUF = {
    key: "map:BPF_MAP_TYPE_RINGBUF"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_USER_RINGBUF = {
    key: "map:BPF_MAP_TYPE_USER_RINGBUF"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_PROG_ARRAY = {
    key: "map:BPF_MAP_TYPE_PROG_ARRAY"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_GLOBAL_DATA_SECTIONS = {
    key: "global:bpf-data-sections"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/commit/d8eca5bbb2be9bc7546f9e733786fa2f1a594c67"
}
