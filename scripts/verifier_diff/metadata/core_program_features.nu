const KERNEL_FEATURE_PROG_RAW_TRACEPOINT = {
    key: "program:BPF_PROG_TYPE_RAW_TRACEPOINT"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_RAW_TRACEPOINT_WRITABLE = {
    key: "section:raw_tracepoint.w"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_SOCKET_FILTER = {
    key: "program:BPF_PROG_TYPE_SOCKET_FILTER"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_KPROBE = {
    key: "program:BPF_PROG_TYPE_KPROBE"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SUBPROGRAM_CALLS = {
    key: "compiled:bpf-subprogram-calls"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BOUNDED_LOOPS = {
    key: "compiled:bounded-loops"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_PROG_SCHED_CLS = {
    key: "program:BPF_PROG_TYPE_SCHED_CLS"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_TRACEPOINT = {
    key: "program:BPF_PROG_TYPE_TRACEPOINT"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_PERF_EVENT = {
    key: "program:BPF_PROG_TYPE_PERF_EVENT"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_TRACING = {
    key: "program:BPF_PROG_TYPE_TRACING"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_LSM = {
    key: "program:BPF_PROG_TYPE_LSM"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_KERNEL_BTF = {
    key: "kernel:btf-vmlinux"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/scripts/link-vmlinux.sh"
}
const KERNEL_FEATURE_BPF_TRAMPOLINE = {
    key: "program:bpf-trampoline"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/kernel/bpf/trampoline.c"
}
const KERNEL_FEATURE_SLEEPABLE_PROGRAM = {
    key: "section:sleepable-program"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_ATTACH_KPROBE_MULTI = {
    key: "attach:BPF_TRACE_KPROBE_MULTI"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
