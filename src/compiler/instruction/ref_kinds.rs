use super::*;

pub fn kfunc_acquire_ref_kind(kfunc: &str) -> Option<KfuncRefKind> {
    match kfunc {
        "bpf_task_acquire" | "bpf_task_from_pid" | "bpf_task_from_vpid" => Some(KfuncRefKind::Task),
        "bpf_task_get_cgroup1" | "bpf_cgroup_acquire" | "bpf_cgroup_from_id" => {
            Some(KfuncRefKind::Cgroup)
        }
        "bpf_get_task_exe_file" => Some(KfuncRefKind::File),
        "bpf_obj_new_impl" | "bpf_refcount_acquire_impl" | "bpf_percpu_obj_new_impl" => {
            Some(KfuncRefKind::Object)
        }
        "scx_bpf_task_cgroup" => Some(KfuncRefKind::Cgroup),
        "scx_bpf_get_online_cpumask"
        | "scx_bpf_get_possible_cpumask"
        | "scx_bpf_get_idle_cpumask"
        | "scx_bpf_get_idle_cpumask_node"
        | "scx_bpf_get_idle_smtmask"
        | "scx_bpf_get_idle_smtmask_node" => Some(KfuncRefKind::Cpumask),
        "bpf_cpumask_create" | "bpf_cpumask_acquire" => Some(KfuncRefKind::Cpumask),
        _ => None,
    }
}

pub fn kfunc_release_ref_kind(kfunc: &str) -> Option<KfuncRefKind> {
    match kfunc {
        "bpf_task_release" => Some(KfuncRefKind::Task),
        "bpf_cgroup_release" => Some(KfuncRefKind::Cgroup),
        "bpf_put_file" => Some(KfuncRefKind::File),
        "bpf_obj_drop_impl" | "bpf_percpu_obj_drop_impl" => Some(KfuncRefKind::Object),
        "bpf_cpumask_release" | "scx_bpf_put_cpumask" | "scx_bpf_put_idle_cpumask" => {
            Some(KfuncRefKind::Cpumask)
        }
        _ => None,
    }
}

pub const fn helper_acquire_ref_kind(helper: BpfHelper) -> Option<KfuncRefKind> {
    match helper {
        BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp | BpfHelper::SkcLookupTcp => {
            Some(KfuncRefKind::Socket)
        }
        _ => None,
    }
}

pub const fn helper_release_ref_kind(helper: BpfHelper) -> Option<KfuncRefKind> {
    match helper {
        BpfHelper::SkRelease => Some(KfuncRefKind::Socket),
        _ => None,
    }
}

pub const fn helper_pointer_arg_ref_kind(
    helper: BpfHelper,
    arg_idx: usize,
) -> Option<KfuncRefKind> {
    match (helper, arg_idx) {
        (
            BpfHelper::SkRelease
            | BpfHelper::SkFullsock
            | BpfHelper::TcpSock
            | BpfHelper::GetListenerSock
            | BpfHelper::TcpCheckSyncookie
            | BpfHelper::TcpGenSyncookie
            | BpfHelper::SkcToTcp6Sock
            | BpfHelper::SkcToTcpSock
            | BpfHelper::SkcToTcpTimewaitSock
            | BpfHelper::SkcToTcpRequestSock
            | BpfHelper::SkcToUdp6Sock
            | BpfHelper::SkcToUnixSock,
            0,
        )
        | (BpfHelper::SkStorageGet | BpfHelper::SkStorageDelete | BpfHelper::SkAssign, 1) => {
            Some(KfuncRefKind::Socket)
        }
        (BpfHelper::TaskStorageGet | BpfHelper::TaskStorageDelete, 1)
        | (BpfHelper::TaskPtRegs, 0) => Some(KfuncRefKind::Task),
        (BpfHelper::InodeStorageGet | BpfHelper::InodeStorageDelete, 1) => {
            Some(KfuncRefKind::Inode)
        }
        (BpfHelper::SockFromFile, 0) => Some(KfuncRefKind::File),
        _ => None,
    }
}

pub fn kfunc_pointer_arg_ref_kind(kfunc: &str, arg_idx: usize) -> Option<KfuncRefKind> {
    if matches!(
        (kfunc, arg_idx),
        ("bpf_task_acquire", 0)
            | ("bpf_task_release", 0)
            | ("bpf_task_get_cgroup1", 0)
            | ("bpf_task_under_cgroup", 0)
            | ("bpf_get_task_exe_file", 0)
            | ("bpf_iter_task_vma_new", 1)
            | ("scx_bpf_dsq_insert", 0)
            | ("scx_bpf_dsq_insert_vtime", 0)
            | ("scx_bpf_dsq_move", 1)
            | ("scx_bpf_dsq_move_vtime", 1)
            | ("scx_bpf_select_cpu_and", 0)
            | ("scx_bpf_select_cpu_dfl", 0)
            | ("scx_bpf_task_cgroup", 0)
            | ("scx_bpf_task_cpu", 0)
            | ("scx_bpf_task_running", 0)
    ) {
        return Some(KfuncRefKind::Task);
    }
    if matches!(
        (kfunc, arg_idx),
        ("bpf_task_under_cgroup", 1)
            | ("bpf_cgroup_acquire", 0)
            | ("bpf_cgroup_ancestor", 0)
            | ("bpf_cgroup_release", 0)
    ) {
        return Some(KfuncRefKind::Cgroup);
    }
    if matches!(
        (kfunc, arg_idx),
        ("bpf_obj_drop_impl", 0)
            | ("bpf_refcount_acquire_impl", 0)
            | ("bpf_percpu_obj_drop_impl", 0)
    ) {
        return Some(KfuncRefKind::Object);
    }
    if matches!((kfunc, arg_idx), ("bpf_put_file", 0)) {
        return Some(KfuncRefKind::File);
    }
    if matches!(
        (kfunc, arg_idx),
        ("bpf_cpumask_acquire", 0)
            | ("bpf_cpumask_release", 0)
            | ("bpf_cpumask_and", 0)
            | ("bpf_cpumask_and", 1)
            | ("bpf_cpumask_and", 2)
            | ("bpf_cpumask_any_and_distribute", 0)
            | ("bpf_cpumask_any_and_distribute", 1)
            | ("bpf_cpumask_any_distribute", 0)
            | ("bpf_cpumask_clear", 0)
            | ("bpf_cpumask_clear_cpu", 1)
            | ("bpf_cpumask_copy", 0)
            | ("bpf_cpumask_copy", 1)
            | ("bpf_cpumask_empty", 0)
            | ("bpf_cpumask_equal", 0)
            | ("bpf_cpumask_equal", 1)
            | ("bpf_cpumask_first", 0)
            | ("bpf_cpumask_first_and", 0)
            | ("bpf_cpumask_first_and", 1)
            | ("bpf_cpumask_first_zero", 0)
            | ("bpf_cpumask_full", 0)
            | ("bpf_cpumask_intersects", 0)
            | ("bpf_cpumask_intersects", 1)
            | ("bpf_cpumask_or", 0)
            | ("bpf_cpumask_or", 1)
            | ("bpf_cpumask_or", 2)
            | ("bpf_cpumask_set_cpu", 1)
            | ("bpf_cpumask_setall", 0)
            | ("bpf_cpumask_subset", 0)
            | ("bpf_cpumask_subset", 1)
            | ("bpf_cpumask_test_and_clear_cpu", 1)
            | ("bpf_cpumask_test_and_set_cpu", 1)
            | ("bpf_cpumask_test_cpu", 1)
            | ("bpf_cpumask_weight", 0)
            | ("bpf_cpumask_xor", 0)
            | ("bpf_cpumask_xor", 1)
            | ("bpf_cpumask_xor", 2)
            | ("scx_bpf_pick_any_cpu", 0)
            | ("scx_bpf_pick_any_cpu_node", 0)
            | ("scx_bpf_pick_idle_cpu", 0)
            | ("scx_bpf_pick_idle_cpu_node", 0)
            | ("scx_bpf_put_cpumask", 0)
            | ("scx_bpf_put_idle_cpumask", 0)
            | ("scx_bpf_select_cpu_and", 3)
    ) {
        return Some(KfuncRefKind::Cpumask);
    }
    None
}

pub fn kfunc_pointer_arg_requires_kernel(kfunc: &str, arg_idx: usize) -> bool {
    if kfunc_pointer_arg_ref_kind(kfunc, arg_idx).is_some() {
        return true;
    }
    matches!(
        (kfunc, arg_idx),
        ("bpf_list_push_front_impl", 0)
            | ("bpf_list_push_front_impl", 1)
            | ("bpf_list_push_back_impl", 0)
            | ("bpf_list_push_back_impl", 1)
            | ("bpf_list_pop_front", 0)
            | ("bpf_list_pop_back", 0)
            | ("bpf_list_front", 0)
            | ("bpf_list_back", 0)
            | ("bpf_path_d_path", 0)
            | ("bpf_map_sum_elem_count", 0)
            | ("bpf_rbtree_remove", 0)
            | ("bpf_rbtree_remove", 1)
            | ("bpf_rbtree_add_impl", 0)
            | ("bpf_rbtree_add_impl", 1)
            | ("bpf_rbtree_first", 0)
            | ("bpf_rbtree_root", 0)
            | ("bpf_rbtree_left", 0)
            | ("bpf_rbtree_right", 0)
    )
}

pub fn kfunc_pointer_arg_requires_stack(kfunc: &str, arg_idx: usize) -> bool {
    matches!(
        (kfunc, arg_idx),
        ("bpf_local_irq_save", 0) | ("bpf_local_irq_restore", 0)
    )
}
