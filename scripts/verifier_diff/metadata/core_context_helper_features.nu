const KERNEL_FEATURE_BPF_KTIME_GET_NS = {
    key: "helper:bpf_ktime_get_ns"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_KTIME_GET_BOOT_NS = {
    key: "helper:bpf_ktime_get_boot_ns"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS = {
    key: "helper:bpf_ktime_get_coarse_ns"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_KTIME_GET_TAI_NS = {
    key: "helper:bpf_ktime_get_tai_ns"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_JIFFIES64 = {
    key: "helper:bpf_jiffies64"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID = {
    key: "helper:bpf_get_current_pid_tgid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_UID_GID = {
    key: "helper:bpf_get_current_uid_gid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_COMM = {
    key: "helper:bpf_get_current_comm"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_SMP_PROCESSOR_ID = {
    key: "helper:bpf_get_smp_processor_id"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
