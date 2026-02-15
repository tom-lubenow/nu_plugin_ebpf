use super::*;
use crate::kernel_btf::KernelBtf;

#[derive(Debug, Clone, Copy)]
pub struct KfuncAllowedPtrSpaces {
    pub allow_stack: bool,
    pub allow_map: bool,
    pub allow_kernel: bool,
    pub allow_user: bool,
}

impl KfuncAllowedPtrSpaces {
    pub const fn new(
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> Self {
        Self {
            allow_stack,
            allow_map,
            allow_kernel,
            allow_user,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KfuncPtrArgRule {
    pub arg_idx: usize,
    pub op: &'static str,
    pub allowed: KfuncAllowedPtrSpaces,
    pub fixed_size: Option<usize>,
    pub size_from_arg: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct KfuncSemantics {
    pub ptr_arg_rules: &'static [KfuncPtrArgRule],
    pub positive_size_args: &'static [usize],
}

pub fn kfunc_semantics(kfunc: &str) -> KfuncSemantics {
    const STACK_MAP: KfuncAllowedPtrSpaces = KfuncAllowedPtrSpaces::new(true, true, false, false);
    const STACK_ONLY: KfuncAllowedPtrSpaces = KfuncAllowedPtrSpaces::new(true, false, false, false);
    const USER_ONLY: KfuncAllowedPtrSpaces = KfuncAllowedPtrSpaces::new(false, false, false, true);
    const NONE: KfuncSemantics = KfuncSemantics {
        ptr_arg_rules: &[],
        positive_size_args: &[],
    };
    const PATH_D_PATH_RULES: &[KfuncPtrArgRule] = &[KfuncPtrArgRule {
        arg_idx: 1,
        op: "kfunc path_d_path buffer",
        allowed: STACK_MAP,
        fixed_size: None,
        size_from_arg: Some(2),
    }];
    const SCX_EVENTS_RULES: &[KfuncPtrArgRule] = &[KfuncPtrArgRule {
        arg_idx: 0,
        op: "kfunc scx_bpf_events events",
        allowed: STACK_MAP,
        fixed_size: None,
        size_from_arg: Some(1),
    }];
    const SCX_DUMP_BSTR_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc scx_bpf_dump_bstr fmt",
            allowed: STACK_MAP,
            fixed_size: Some(1),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 1,
            op: "kfunc scx_bpf_dump_bstr data",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(2),
        },
    ];
    const SCX_ERROR_BSTR_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc scx_bpf_error_bstr fmt",
            allowed: STACK_MAP,
            fixed_size: Some(1),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 1,
            op: "kfunc scx_bpf_error_bstr data",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(2),
        },
    ];
    const SCX_EXIT_BSTR_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 1,
            op: "kfunc scx_bpf_exit_bstr fmt",
            allowed: STACK_MAP,
            fixed_size: Some(1),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 2,
            op: "kfunc scx_bpf_exit_bstr data",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(3),
        },
    ];
    const COPY_FROM_USER_STR_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc bpf_copy_from_user_str dst",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(1),
        },
        KfuncPtrArgRule {
            arg_idx: 2,
            op: "kfunc bpf_copy_from_user_str src",
            allowed: USER_ONLY,
            fixed_size: None,
            size_from_arg: Some(1),
        },
    ];
    const COPY_FROM_USER_TASK_STR_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc bpf_copy_from_user_task_str dst",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(1),
        },
        KfuncPtrArgRule {
            arg_idx: 2,
            op: "kfunc bpf_copy_from_user_task_str src",
            allowed: USER_ONLY,
            fixed_size: None,
            size_from_arg: Some(1),
        },
    ];
    const COPY_FROM_USER_DYNPTR_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc bpf_copy_from_user_dynptr dptr",
            allowed: STACK_ONLY,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 3,
            op: "kfunc bpf_copy_from_user_dynptr src",
            allowed: USER_ONLY,
            fixed_size: None,
            size_from_arg: Some(2),
        },
    ];
    const COPY_FROM_USER_TASK_DYNPTR_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc bpf_copy_from_user_task_dynptr dptr",
            allowed: STACK_ONLY,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 3,
            op: "kfunc bpf_copy_from_user_task_dynptr src",
            allowed: USER_ONLY,
            fixed_size: None,
            size_from_arg: Some(2),
        },
    ];
    const DYNPTR_ADJUST_RULES: &[KfuncPtrArgRule] = &[KfuncPtrArgRule {
        arg_idx: 0,
        op: "kfunc bpf_dynptr_adjust p",
        allowed: STACK_ONLY,
        fixed_size: Some(16),
        size_from_arg: None,
    }];
    const DYNPTR_CLONE_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc bpf_dynptr_clone src",
            allowed: STACK_ONLY,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 1,
            op: "kfunc bpf_dynptr_clone dst",
            allowed: STACK_ONLY,
            fixed_size: Some(16),
            size_from_arg: None,
        },
    ];
    const DYNPTR_COPY_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc bpf_dynptr_copy dst",
            allowed: STACK_ONLY,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 2,
            op: "kfunc bpf_dynptr_copy src",
            allowed: STACK_ONLY,
            fixed_size: Some(16),
            size_from_arg: None,
        },
    ];
    const DYNPTR_SIZE_RULES: &[KfuncPtrArgRule] = &[KfuncPtrArgRule {
        arg_idx: 0,
        op: "kfunc bpf_dynptr_size p",
        allowed: STACK_ONLY,
        fixed_size: Some(16),
        size_from_arg: None,
    }];
    const DYNPTR_MEMSET_RULES: &[KfuncPtrArgRule] = &[KfuncPtrArgRule {
        arg_idx: 0,
        op: "kfunc bpf_dynptr_memset p",
        allowed: STACK_ONLY,
        fixed_size: Some(16),
        size_from_arg: None,
    }];
    const DYNPTR_SLICE_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc bpf_dynptr_slice p",
            allowed: STACK_ONLY,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 2,
            op: "kfunc bpf_dynptr_slice buffer",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(3),
        },
    ];
    const CRYPTO_CTX_CREATE_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 0,
            op: "kfunc bpf_crypto_ctx_create params",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(1),
        },
        KfuncPtrArgRule {
            arg_idx: 2,
            op: "kfunc bpf_crypto_ctx_create err",
            allowed: STACK_MAP,
            fixed_size: Some(4),
            size_from_arg: None,
        },
    ];
    const CRYPTO_ENCRYPT_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 1,
            op: "kfunc bpf_crypto_encrypt src",
            allowed: STACK_MAP,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 2,
            op: "kfunc bpf_crypto_encrypt dst",
            allowed: STACK_MAP,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 3,
            op: "kfunc bpf_crypto_encrypt siv",
            allowed: STACK_MAP,
            fixed_size: Some(16),
            size_from_arg: None,
        },
    ];
    const CRYPTO_DECRYPT_RULES: &[KfuncPtrArgRule] = &[
        KfuncPtrArgRule {
            arg_idx: 1,
            op: "kfunc bpf_crypto_decrypt src",
            allowed: STACK_MAP,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 2,
            op: "kfunc bpf_crypto_decrypt dst",
            allowed: STACK_MAP,
            fixed_size: Some(16),
            size_from_arg: None,
        },
        KfuncPtrArgRule {
            arg_idx: 3,
            op: "kfunc bpf_crypto_decrypt siv",
            allowed: STACK_MAP,
            fixed_size: Some(16),
            size_from_arg: None,
        },
    ];

    match kfunc {
        "bpf_path_d_path" => KfuncSemantics {
            ptr_arg_rules: PATH_D_PATH_RULES,
            positive_size_args: &[2],
        },
        "bpf_copy_from_user_str" => KfuncSemantics {
            ptr_arg_rules: COPY_FROM_USER_STR_RULES,
            positive_size_args: &[1],
        },
        "bpf_copy_from_user_dynptr" => KfuncSemantics {
            ptr_arg_rules: COPY_FROM_USER_DYNPTR_RULES,
            positive_size_args: &[2],
        },
        "bpf_copy_from_user_task_str" => KfuncSemantics {
            ptr_arg_rules: COPY_FROM_USER_TASK_STR_RULES,
            positive_size_args: &[1],
        },
        "bpf_copy_from_user_task_dynptr" | "bpf_copy_from_user_task_str_dynptr" => KfuncSemantics {
            ptr_arg_rules: COPY_FROM_USER_TASK_DYNPTR_RULES,
            positive_size_args: &[2],
        },
        "bpf_dynptr_adjust" => KfuncSemantics {
            ptr_arg_rules: DYNPTR_ADJUST_RULES,
            positive_size_args: &[],
        },
        "bpf_dynptr_clone" => KfuncSemantics {
            ptr_arg_rules: DYNPTR_CLONE_RULES,
            positive_size_args: &[],
        },
        "bpf_dynptr_copy" => KfuncSemantics {
            ptr_arg_rules: DYNPTR_COPY_RULES,
            positive_size_args: &[],
        },
        "bpf_dynptr_size" | "bpf_dynptr_is_null" | "bpf_dynptr_is_rdonly" => KfuncSemantics {
            ptr_arg_rules: DYNPTR_SIZE_RULES,
            positive_size_args: &[],
        },
        "bpf_dynptr_memset" => KfuncSemantics {
            ptr_arg_rules: DYNPTR_MEMSET_RULES,
            positive_size_args: &[],
        },
        "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr" => KfuncSemantics {
            ptr_arg_rules: DYNPTR_SLICE_RULES,
            positive_size_args: &[],
        },
        "bpf_crypto_ctx_create" => KfuncSemantics {
            ptr_arg_rules: CRYPTO_CTX_CREATE_RULES,
            positive_size_args: &[1],
        },
        "bpf_crypto_encrypt" => KfuncSemantics {
            ptr_arg_rules: CRYPTO_ENCRYPT_RULES,
            positive_size_args: &[],
        },
        "bpf_crypto_decrypt" => KfuncSemantics {
            ptr_arg_rules: CRYPTO_DECRYPT_RULES,
            positive_size_args: &[],
        },
        "scx_bpf_events" => KfuncSemantics {
            ptr_arg_rules: SCX_EVENTS_RULES,
            positive_size_args: &[1],
        },
        "scx_bpf_dump_bstr" => KfuncSemantics {
            ptr_arg_rules: SCX_DUMP_BSTR_RULES,
            positive_size_args: &[2],
        },
        "scx_bpf_error_bstr" => KfuncSemantics {
            ptr_arg_rules: SCX_ERROR_BSTR_RULES,
            positive_size_args: &[2],
        },
        "scx_bpf_exit_bstr" => KfuncSemantics {
            ptr_arg_rules: SCX_EXIT_BSTR_RULES,
            positive_size_args: &[3],
        },
        _ => NONE,
    }
}

pub fn kfunc_acquire_ref_kind(kfunc: &str) -> Option<KfuncRefKind> {
    match kfunc {
        "bpf_task_acquire" | "bpf_task_from_pid" | "bpf_task_from_vpid" => Some(KfuncRefKind::Task),
        "bpf_task_get_cgroup1" | "bpf_cgroup_acquire" | "bpf_cgroup_from_id" => {
            Some(KfuncRefKind::Cgroup)
        }
        "bpf_get_task_exe_file" => Some(KfuncRefKind::File),
        "bpf_crypto_ctx_acquire" | "bpf_crypto_ctx_create" => Some(KfuncRefKind::CryptoCtx),
        "bpf_obj_new_impl"
        | "bpf_refcount_acquire_impl"
        | "bpf_percpu_obj_new_impl"
        | "bpf_list_pop_front"
        | "bpf_list_pop_back"
        | "bpf_rbtree_remove" => Some(KfuncRefKind::Object),
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
        "bpf_crypto_ctx_release" => Some(KfuncRefKind::CryptoCtx),
        "bpf_obj_drop_impl"
        | "bpf_percpu_obj_drop_impl"
        | "bpf_list_push_front_impl"
        | "bpf_list_push_back_impl"
        | "bpf_rbtree_add_impl" => Some(KfuncRefKind::Object),
        "bpf_cpumask_release"
        | "bpf_cpumask_release_dtor"
        | "scx_bpf_put_cpumask"
        | "scx_bpf_put_idle_cpumask" => Some(KfuncRefKind::Cpumask),
        _ => None,
    }
}

pub fn kfunc_release_ref_arg_index(kfunc: &str) -> Option<usize> {
    match kfunc {
        "bpf_list_push_front_impl" | "bpf_list_push_back_impl" | "bpf_rbtree_add_impl" => Some(1),
        _ if kfunc_release_ref_kind(kfunc).is_some() => Some(0),
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
            | ("bpf_iter_task_new", 1)
            | ("bpf_copy_from_user_task_str", 3)
            | ("bpf_copy_from_user_task_dynptr", 4)
            | ("bpf_copy_from_user_task_str_dynptr", 4)
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
        ("bpf_crypto_ctx_acquire", 0)
            | ("bpf_crypto_ctx_release", 0)
            | ("bpf_crypto_encrypt", 0)
            | ("bpf_crypto_decrypt", 0)
    ) {
        return Some(KfuncRefKind::CryptoCtx);
    }
    if matches!(
        (kfunc, arg_idx),
        ("bpf_task_under_cgroup", 1)
            | ("bpf_cgroup_acquire", 0)
            | ("bpf_cgroup_ancestor", 0)
            | ("bpf_iter_css_new", 1)
            | ("bpf_iter_css_task_new", 1)
            | ("bpf_cgroup_release", 0)
    ) {
        return Some(KfuncRefKind::Cgroup);
    }
    if matches!(
        (kfunc, arg_idx),
        ("bpf_obj_drop_impl", 0)
            | ("bpf_refcount_acquire_impl", 0)
            | ("bpf_percpu_obj_drop_impl", 0)
            | ("bpf_list_push_front_impl", 1)
            | ("bpf_list_push_back_impl", 1)
            | ("bpf_rbtree_add_impl", 1)
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
            | ("bpf_cpumask_release_dtor", 0)
            | ("bpf_cpumask_populate", 0)
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
            | ("scx_bpf_select_cpu_dfl", 3)
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
            | ("bpf_res_spin_lock", 0)
            | ("bpf_res_spin_unlock", 0)
            | ("bpf_res_spin_lock_irqsave", 0)
            | ("bpf_res_spin_unlock_irqrestore", 0)
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
        ("bpf_local_irq_save", 0)
            | ("bpf_local_irq_restore", 0)
            | ("bpf_res_spin_lock_irqsave", 1)
            | ("bpf_res_spin_unlock_irqrestore", 1)
            | ("bpf_iter_task_vma_new", 0)
            | ("bpf_iter_task_vma_next", 0)
            | ("bpf_iter_task_vma_destroy", 0)
            | ("bpf_iter_task_new", 0)
            | ("bpf_iter_task_next", 0)
            | ("bpf_iter_task_destroy", 0)
            | ("bpf_iter_num_new", 0)
            | ("bpf_iter_num_next", 0)
            | ("bpf_iter_num_destroy", 0)
            | ("bpf_iter_bits_new", 0)
            | ("bpf_iter_bits_next", 0)
            | ("bpf_iter_bits_destroy", 0)
            | ("bpf_iter_css_new", 0)
            | ("bpf_iter_css_next", 0)
            | ("bpf_iter_css_destroy", 0)
            | ("bpf_iter_css_task_new", 0)
            | ("bpf_iter_css_task_next", 0)
            | ("bpf_iter_css_task_destroy", 0)
            | ("bpf_iter_dmabuf_new", 0)
            | ("bpf_iter_dmabuf_next", 0)
            | ("bpf_iter_dmabuf_destroy", 0)
            | ("bpf_iter_kmem_cache_new", 0)
            | ("bpf_iter_kmem_cache_next", 0)
            | ("bpf_iter_kmem_cache_destroy", 0)
            | ("bpf_iter_scx_dsq_new", 0)
            | ("bpf_iter_scx_dsq_next", 0)
            | ("bpf_iter_scx_dsq_destroy", 0)
            | ("bpf_copy_from_user_dynptr", 0)
            | ("bpf_copy_from_user_task_dynptr", 0)
            | ("bpf_copy_from_user_task_str_dynptr", 0)
            | ("bpf_dynptr_adjust", 0)
            | ("bpf_dynptr_clone", 0)
            | ("bpf_dynptr_clone", 1)
            | ("bpf_dynptr_copy", 0)
            | ("bpf_dynptr_copy", 2)
            | ("bpf_dynptr_size", 0)
            | ("bpf_dynptr_is_null", 0)
            | ("bpf_dynptr_is_rdonly", 0)
            | ("bpf_dynptr_memset", 0)
            | ("bpf_dynptr_slice", 0)
            | ("bpf_dynptr_slice_rdwr", 0)
            | ("scx_bpf_dsq_move", 0)
            | ("scx_bpf_dsq_move_set_slice", 0)
            | ("scx_bpf_dsq_move_set_vtime", 0)
            | ("scx_bpf_dsq_move_vtime", 0)
    )
}

pub fn kfunc_pointer_arg_requires_stack_slot_base(kfunc: &str, arg_idx: usize) -> bool {
    matches!(
        (kfunc, arg_idx),
        ("bpf_path_d_path", 1)
            | ("scx_bpf_events", 0)
            | ("bpf_copy_from_user_str", 0)
            | ("bpf_copy_from_user_task_str", 0)
            | ("bpf_copy_from_user_dynptr", 0)
            | ("bpf_copy_from_user_task_dynptr", 0)
            | ("bpf_copy_from_user_task_str_dynptr", 0)
            | ("bpf_dynptr_adjust", 0)
            | ("bpf_dynptr_clone", 0)
            | ("bpf_dynptr_clone", 1)
            | ("bpf_dynptr_copy", 0)
            | ("bpf_dynptr_copy", 2)
            | ("bpf_dynptr_size", 0)
            | ("bpf_dynptr_is_null", 0)
            | ("bpf_dynptr_is_rdonly", 0)
            | ("bpf_dynptr_memset", 0)
            | ("bpf_dynptr_slice", 0)
            | ("bpf_dynptr_slice", 2)
            | ("bpf_dynptr_slice_rdwr", 0)
            | ("bpf_dynptr_slice_rdwr", 2)
            | ("bpf_crypto_ctx_create", 0)
            | ("bpf_crypto_ctx_create", 2)
            | ("bpf_crypto_encrypt", 1)
            | ("bpf_crypto_encrypt", 2)
            | ("bpf_crypto_encrypt", 3)
            | ("bpf_crypto_decrypt", 1)
            | ("bpf_crypto_decrypt", 2)
            | ("bpf_crypto_decrypt", 3)
            | ("scx_bpf_dump_bstr", 0)
            | ("scx_bpf_dump_bstr", 1)
            | ("scx_bpf_error_bstr", 0)
            | ("scx_bpf_error_bstr", 1)
            | ("scx_bpf_exit_bstr", 1)
            | ("scx_bpf_exit_bstr", 2)
    )
}

pub fn kfunc_pointer_arg_allows_const_zero(kfunc: &str, arg_idx: usize) -> bool {
    matches!(
        (kfunc, arg_idx),
        ("bpf_crypto_encrypt", 3)
            | ("bpf_crypto_decrypt", 3)
            | ("bpf_iter_task_new", 1)
            | ("bpf_dynptr_slice", 2)
            | ("bpf_dynptr_slice_rdwr", 2)
    ) || KernelBtf::get().kfunc_pointer_arg_is_nullable(kfunc, arg_idx)
}
