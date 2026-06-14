# Keep this table aligned with `KfuncCompatibilityRequirement` in Rust.
# Explicit records in `KFUNC_KERNEL_FEATURES` still win when the harness needs a named feature constant.
let KFUNC_KERNEL_FEATURE_FALLBACKS = (
    [
    { name: "bpf_list_back", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_list_front", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_list_pop_back", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_list_pop_front", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_list_push_back_impl", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_list_push_front_impl", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_local_irq_restore", min_kernel: "6.14", source: "https://github.com/torvalds/linux/blob/v6.14/kernel/bpf/helpers.c" }
    { name: "bpf_local_irq_save", min_kernel: "6.14", source: "https://github.com/torvalds/linux/blob/v6.14/kernel/bpf/helpers.c" }
    { name: "bpf_map_sum_elem_count", min_kernel: "6.6", source: "https://github.com/torvalds/linux/blob/v6.6/kernel/bpf/map_iter.c" }
    { name: "bpf_wq_init", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_wq_set_callback_impl", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_wq_start", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_obj_drop_impl", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_obj_new_impl", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_path_d_path", min_kernel: "6.18", source: "https://github.com/torvalds/linux/blob/v6.18/fs/bpf_fs_kfuncs.c" }
    { name: "bpf_percpu_obj_drop_impl", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_percpu_obj_new_impl", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_preempt_disable", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_preempt_enable", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_put_file", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c" }
    { name: "bpf_rbtree_add_impl", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_first", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_left", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_remove", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_right", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_root", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_rcu_read_lock", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_rcu_read_unlock", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_refcount_acquire_impl", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_res_spin_lock", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c" }
    { name: "bpf_res_spin_lock_irqsave", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c" }
    { name: "bpf_res_spin_unlock", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c" }
    { name: "bpf_res_spin_unlock_irqrestore", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c" }
    { name: "bpf_sock_addr_set_sun_path", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/net/core/filter.c" }
    { name: "bpf_sock_ops_enable_tx_tstamp", min_kernel: "6.18", source: "https://github.com/torvalds/linux/blob/v6.18/net/core/filter.c" }
    { name: "bpf_task_acquire", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_task_from_pid", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_task_from_vpid", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/helpers.c" }
    { name: "bpf_task_get_cgroup1", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/helpers.c" }
    { name: "bpf_task_release", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_task_under_cgroup", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_throw", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_xdp_get_xfrm_state", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/net/xfrm/xfrm_state_bpf.c" }
    { name: "bpf_xdp_metadata_rx_hash", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/net/core/xdp.c" }
    { name: "bpf_xdp_metadata_rx_timestamp", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/net/core/xdp.c" }
    { name: "bpf_xdp_metadata_rx_vlan_tag", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/net/core/xdp.c" }
    { name: "bpf_xdp_xfrm_state_release", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/net/xfrm/xfrm_state_bpf.c" }
    ]
    | append $OBJECT_DYNPTR_KFUNC_KERNEL_FEATURE_FALLBACKS
    | append $ITER_KFUNC_KERNEL_FEATURE_FALLBACKS
    | append $CPUMASK_KFUNC_KERNEL_FEATURE_FALLBACKS
    | append $SCHED_EXT_KFUNC_KERNEL_FEATURE_FALLBACKS
)
