const KERNEL_FEATURE_MAP_VALUE_BPF_SPIN_LOCK = {
    key: "map-value:bpf_spin_lock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_TIMER = {
    key: "map-value:bpf_timer"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_KPTR = {
    key: "map-value:kptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_WQ = {
    key: "map-value:bpf_wq"
    min_kernel: "6.10"
    source: "https://github.com/torvalds/linux/blob/v6.10/include/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_REFCOUNT = {
    key: "map-value:bpf_refcount"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_LIST_HEAD = {
    key: "map-value:bpf_list_head"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_LIST_NODE = {
    key: "map-value:bpf_list_node"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_RB_ROOT = {
    key: "map-value:bpf_rb_root"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_RB_NODE = {
    key: "map-value:bpf_rb_node"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_BPF_KPTR_XCHG = {
    key: "helper:bpf_kptr_xchg"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_KFUNC_BPF_TASK_ACQUIRE = {
    key: "kfunc:bpf_task_acquire"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_TASK_FROM_PID = {
    key: "kfunc:bpf_task_from_pid"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_TASK_RELEASE = {
    key: "kfunc:bpf_task_release"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CGROUP_ACQUIRE = {
    key: "kfunc:bpf_cgroup_acquire"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CGROUP_ANCESTOR = {
    key: "kfunc:bpf_cgroup_ancestor"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CGROUP_FROM_ID = {
    key: "kfunc:bpf_cgroup_from_id"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE = {
    key: "kfunc:bpf_cgroup_release"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_GET_TASK_EXE_FILE = {
    key: "kfunc:bpf_get_task_exe_file"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c"
}
const KERNEL_FEATURE_KFUNC_BPF_PUT_FILE = {
    key: "kfunc:bpf_put_file"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE = {
    key: "kfunc:bpf_cpumask_create"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_ACQUIRE = {
    key: "kfunc:bpf_cpumask_acquire"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE = {
    key: "kfunc:bpf_cpumask_release"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_FIRST = {
    key: "kfunc:bpf_cpumask_first"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_SET_CPU = {
    key: "kfunc:bpf_cpumask_set_cpu"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
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
const KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT = {
    key: "kfunc:scx_bpf_dsq_insert"
    min_kernel: "6.13"
    max_kernel_exclusive: "6.23"
    max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c"
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT_V2 = {
    key: "kfunc:scx_bpf_dsq_insert___v2"
    min_kernel: "6.19"
    source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT_VTIME = {
    key: "kfunc:scx_bpf_dsq_insert_vtime"
    min_kernel: "6.13"
    max_kernel_exclusive: "6.23"
    max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c"
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_REENQUEUE_LOCAL = {
    key: "kfunc:scx_bpf_reenqueue_local"
    min_kernel: "6.12"
    max_kernel_exclusive: "6.23"
    max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_REENQUEUE_LOCAL_V2 = {
    key: "kfunc:scx_bpf_reenqueue_local___v2"
    min_kernel: "6.19"
    source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_CPUMASK = {
    key: "kfunc:scx_bpf_get_idle_cpumask"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_SMTMASK = {
    key: "kfunc:scx_bpf_get_idle_smtmask"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_ANY_CPU = {
    key: "kfunc:scx_bpf_pick_any_cpu"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PUT_IDLE_CPUMASK = {
    key: "kfunc:scx_bpf_put_idle_cpumask"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_CPU_NODE = {
    key: "kfunc:scx_bpf_cpu_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_CPUMASK_NODE = {
    key: "kfunc:scx_bpf_get_idle_cpumask_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_SMTMASK_NODE = {
    key: "kfunc:scx_bpf_get_idle_smtmask_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_ANY_CPU_NODE = {
    key: "kfunc:scx_bpf_pick_any_cpu_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_IDLE_CPU_NODE = {
    key: "kfunc:scx_bpf_pick_idle_cpu_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_BPF_USER_RINGBUF_DRAIN = {
    key: "helper:bpf_user_ringbuf_drain"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h"
}
