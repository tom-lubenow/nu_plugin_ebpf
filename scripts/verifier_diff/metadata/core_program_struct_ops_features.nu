const KERNEL_FEATURE_PROG_STRUCT_OPS = {
    key: "program:BPF_PROG_TYPE_STRUCT_OPS"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_STRUCT_OPS_TCP_CONGESTION = {
    key: "struct_ops:tcp_congestion_ops"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/net/ipv4/bpf_tcp_ca.c"
}
const KERNEL_FEATURE_STRUCT_OPS_HID_BPF = {
    key: "struct_ops:hid_bpf_ops"
    min_kernel: "6.11"
    source: "https://github.com/torvalds/linux/blob/v6.11/drivers/hid/bpf/hid_bpf_struct_ops.c"
}
const KERNEL_FEATURE_STRUCT_OPS_SCHED_EXT = {
    key: "struct_ops:sched_ext_ops"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_STRUCT_OPS_QDISC = {
    key: "struct_ops:Qdisc_ops"
    min_kernel: "6.16"
    source: "https://github.com/torvalds/linux/blob/v6.16/net/sched/bpf_qdisc.c"
}
const SCHED_EXT_SLEEPABLE_CALLBACKS = [
    init_task
    cgroup_init
    cgroup_exit
    cgroup_prep_move
    cpu_online
    cpu_offline
    init
    exit
]
