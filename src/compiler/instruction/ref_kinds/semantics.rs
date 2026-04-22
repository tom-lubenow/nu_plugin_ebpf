use super::{KfuncAllowedPtrSpaces, KfuncPtrArgRule, KfuncSemantics};

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
    const SOCK_ADDR_SET_SUN_PATH_RULES: &[KfuncPtrArgRule] = &[KfuncPtrArgRule {
        arg_idx: 1,
        op: "kfunc bpf_sock_addr_set_sun_path path",
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
    const SCX_SELECT_CPU_DFL_RULES: &[KfuncPtrArgRule] = &[KfuncPtrArgRule {
        arg_idx: 3,
        op: "kfunc scx_bpf_select_cpu_dfl is_idle",
        allowed: STACK_ONLY,
        fixed_size: Some(1),
        size_from_arg: None,
    }];
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
        "bpf_sock_addr_set_sun_path" => KfuncSemantics {
            ptr_arg_rules: SOCK_ADDR_SET_SUN_PATH_RULES,
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
            positive_size_args: &[3],
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
        "scx_bpf_select_cpu_dfl" => KfuncSemantics {
            ptr_arg_rules: SCX_SELECT_CPU_DFL_RULES,
            positive_size_args: &[],
        },
        _ => NONE,
    }
}
