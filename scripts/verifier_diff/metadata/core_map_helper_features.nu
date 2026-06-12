const KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM = {
    key: "helper:bpf_map_lookup_elem"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM = {
    key: "helper:bpf_map_update_elem"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_DELETE_ELEM = {
    key: "helper:bpf_map_delete_elem"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_PUSH_ELEM = {
    key: "helper:bpf_map_push_elem"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_POP_ELEM = {
    key: "helper:bpf_map_pop_elem"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_PEEK_ELEM = {
    key: "helper:bpf_map_peek_elem"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SOCK_MAP_UPDATE = {
    key: "helper:bpf_sock_map_update"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SOCK_HASH_UPDATE = {
    key: "helper:bpf_sock_hash_update"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_STORAGE_GET = {
    key: "helper:bpf_sk_storage_get"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_STORAGE_DELETE = {
    key: "helper:bpf_sk_storage_delete"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_INODE_STORAGE_GET = {
    key: "helper:bpf_inode_storage_get"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_INODE_STORAGE_DELETE = {
    key: "helper:bpf_inode_storage_delete"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TASK_STORAGE_GET = {
    key: "helper:bpf_task_storage_get"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TASK_STORAGE_DELETE = {
    key: "helper:bpf_task_storage_delete"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CGRP_STORAGE_GET = {
    key: "helper:bpf_cgrp_storage_get"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CGRP_STORAGE_DELETE = {
    key: "helper:bpf_cgrp_storage_delete"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h"
}
