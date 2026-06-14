const KERNEL_FEATURE_BPF_PROBE_READ = {
    key: "helper:bpf_probe_read"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_STR = {
    key: "helper:bpf_probe_read_str"
    min_kernel: "4.11"
    source: "https://github.com/torvalds/linux/blob/v4.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_USER = {
    key: "helper:bpf_probe_read_user"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_KERNEL = {
    key: "helper:bpf_probe_read_kernel"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_USER_STR = {
    key: "helper:bpf_probe_read_user_str"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR = {
    key: "helper:bpf_probe_read_kernel_str"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_PRANDOM_U32 = {
    key: "helper:bpf_get_prandom_u32"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_STACKID = {
    key: "helper:bpf_get_stackid"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_STACK = {
    key: "helper:bpf_get_stack"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TAIL_CALL = {
    key: "helper:bpf_tail_call"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_EVENT_READ = {
    key: "helper:bpf_perf_event_read"
    min_kernel: "4.3"
    source: "https://github.com/torvalds/linux/blob/v4.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_EVENT_READ_VALUE = {
    key: "helper:bpf_perf_event_read_value"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE = {
    key: "helper:bpf_perf_prog_read_value"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_OVERRIDE_RETURN = {
    key: "helper:bpf_override_return"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
