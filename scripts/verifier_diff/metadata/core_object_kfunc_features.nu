const KERNEL_FEATURE_BPF_KPTR_XCHG = {
    key: "helper:bpf_kptr_xchg"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_LOCK = {
    key: "kfunc:bpf_res_spin_lock"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_UNLOCK = {
    key: "kfunc:bpf_res_spin_unlock"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_LOCK_IRQSAVE = {
    key: "kfunc:bpf_res_spin_lock_irqsave"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_UNLOCK_IRQRESTORE = {
    key: "kfunc:bpf_res_spin_unlock_irqrestore"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_KFUNC_BPF_SOCK_ADDR_SET_SUN_PATH = {
    key: "kfunc:bpf_sock_addr_set_sun_path"
    min_kernel: "6.7"
    source: "https://github.com/torvalds/linux/blob/v6.7/net/core/filter.c"
}
const KERNEL_FEATURE_KFUNC_BPF_SOCK_OPS_ENABLE_TX_TSTAMP = {
    key: "kfunc:bpf_sock_ops_enable_tx_tstamp"
    min_kernel: "6.18"
    source: "https://github.com/torvalds/linux/blob/v6.18/net/core/filter.c"
}
