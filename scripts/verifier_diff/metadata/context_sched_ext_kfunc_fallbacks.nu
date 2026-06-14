const SCHED_EXT_KFUNC_KERNEL_FEATURE_FALLBACKS = [
    { name: "scx_bpf_cpu_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_cpu_rq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_cap", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_cur", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_set", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_create_dsq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_destroy_dsq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dispatch_cancel", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dispatch_nr_slots", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_insert", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c", max_kernel_exclusive: "6.23", max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_insert___v2", min_kernel: "6.19", source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_insert_vtime", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c", max_kernel_exclusive: "6.23", max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move_set_slice", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move_set_vtime", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move_to_local", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move_vtime", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_nr_queued", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dump_bstr", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_error_bstr", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_events", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext.c" }
    { name: "scx_bpf_exit_bstr", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_get_idle_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_get_idle_cpumask_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_get_idle_smtmask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_get_idle_smtmask_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_get_online_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_get_possible_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_kick_cpu", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_now", min_kernel: "6.14", source: "https://github.com/torvalds/linux/blob/v6.14/kernel/sched/ext.c" }
    { name: "scx_bpf_nr_cpu_ids", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_nr_node_ids", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext.c" }
    { name: "scx_bpf_pick_any_cpu", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_pick_any_cpu_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_pick_idle_cpu", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_pick_idle_cpu_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_put_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_put_idle_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_reenqueue_local", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c", max_kernel_exclusive: "6.23", max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c" }
    { name: "scx_bpf_reenqueue_local___v2", min_kernel: "6.19", source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c" }
    { name: "scx_bpf_select_cpu_and", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/sched/ext.c" }
    { name: "scx_bpf_select_cpu_dfl", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_task_cgroup", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_task_cpu", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_task_running", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_test_and_clear_cpu_idle", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
]
