use super::*;
use crate::kernel_btf::{KernelBtf, KfuncPointerRefFamily};
use std::collections::{BTreeMap, BTreeSet};

fn ref_kind_from_btf_family(family: KfuncPointerRefFamily) -> KfuncRefKind {
    match family {
        KfuncPointerRefFamily::Task => KfuncRefKind::Task,
        KfuncPointerRefFamily::Cgroup => KfuncRefKind::Cgroup,
        KfuncPointerRefFamily::Inode => KfuncRefKind::Inode,
        KfuncPointerRefFamily::Cpumask => KfuncRefKind::Cpumask,
        KfuncPointerRefFamily::CryptoCtx => KfuncRefKind::CryptoCtx,
        KfuncPointerRefFamily::File => KfuncRefKind::File,
        KfuncPointerRefFamily::Socket => KfuncRefKind::Socket,
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncIterFamily {
    TaskVma,
    Task,
    ScxDsq,
    Num,
    Bits,
    Css,
    CssTask,
    Dmabuf,
    KmemCache,
}

impl KfuncIterFamily {
    pub const fn constructor_kfunc(self) -> &'static str {
        match self {
            Self::TaskVma => "bpf_iter_task_vma_new",
            Self::Task => "bpf_iter_task_new",
            Self::ScxDsq => "bpf_iter_scx_dsq_new",
            Self::Num => "bpf_iter_num_new",
            Self::Bits => "bpf_iter_bits_new",
            Self::Css => "bpf_iter_css_new",
            Self::CssTask => "bpf_iter_css_task_new",
            Self::Dmabuf => "bpf_iter_dmabuf_new",
            Self::KmemCache => "bpf_iter_kmem_cache_new",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncIterLifecycleOp {
    New,
    Next,
    Destroy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KfuncUnknownIterLifecycle {
    pub family: KfuncIterFamily,
    pub op: KfuncIterLifecycleOp,
    pub arg_idx: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncUnknownDynptrArgRole {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KfuncUnknownDynptrArg {
    pub arg_idx: usize,
    pub role: KfuncUnknownDynptrArgRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KfuncUnknownDynptrCopy {
    pub src_arg_idx: usize,
    pub dst_arg_idx: usize,
    pub move_semantics: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncUnknownStackObjectLifecycleOp {
    Init,
    Destroy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KfuncUnknownStackObjectLifecycle {
    pub type_name: String,
    pub op: KfuncUnknownStackObjectLifecycleOp,
    pub arg_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KfuncUnknownStackObjectCopy {
    pub type_name: String,
    pub src_arg_idx: usize,
    pub dst_arg_idx: usize,
    pub move_semantics: bool,
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

fn should_infer_unknown_acquire_ref(
    kfunc: &str,
    kind: KfuncRefKind,
    has_same_family_arg: bool,
    has_const_only_same_family_args: bool,
) -> bool {
    kfunc.contains("_acquire")
        || kfunc.contains("_from_")
        || kfunc.contains("_create")
        || kfunc.contains("_alloc")
        || kfunc.starts_with("bpf_get_")
        || kfunc.starts_with("scx_bpf_get_")
        || kfunc.contains("_get_")
        || kfunc.ends_with("_get")
        || kfunc.contains("_dup")
        || kfunc.contains("_clone")
        || (kind == KfuncRefKind::Socket && kfunc.contains("lookup"))
        || !has_same_family_arg
        || has_const_only_same_family_args
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
        _ => {
            if KfuncSignature::for_name(kfunc).is_none() {
                let kernel_btf = KernelBtf::get();
                let Some(kind) = kernel_btf
                    .kfunc_return_ref_family(kfunc)
                    .map(ref_kind_from_btf_family)
                else {
                    return None;
                };
                let mut has_same_family_arg = false;
                let mut has_non_const_same_family_arg = false;
                for arg_idx in 0..5 {
                    if kernel_btf
                        .kfunc_pointer_arg_ref_family(kfunc, arg_idx)
                        .map(ref_kind_from_btf_family)
                        != Some(kind)
                    {
                        continue;
                    }
                    has_same_family_arg = true;
                    if !kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx) {
                        has_non_const_same_family_arg = true;
                    }
                }
                let has_const_only_same_family_args =
                    has_same_family_arg && !has_non_const_same_family_arg;
                if should_infer_unknown_acquire_ref(
                    kfunc,
                    kind,
                    has_same_family_arg,
                    has_const_only_same_family_args,
                ) {
                    return Some(kind);
                }
            }
            None
        }
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
        _ => {
            if KfuncSignature::for_name(kfunc).is_none()
                && (kfunc.contains("_release")
                    || kfunc.contains("_destroy")
                    || kfunc.contains("_delete")
                    || kfunc.contains("_detach")
                    || kfunc.contains("_close")
                    || kfunc.contains("_unref")
                    || kfunc.starts_with("bpf_put_")
                    || kfunc.contains("_put_")
                    || kfunc.ends_with("_put")
                    || kfunc.contains("_drop")
                    || kfunc.contains("_free")
                    || kfunc.contains("_dec_")
                    || kfunc.ends_with("_dec"))
            {
                let kernel_btf = KernelBtf::get();
                if let Some(release_arg_idx) = kernel_btf.kfunc_release_ref_arg_index(kfunc) {
                    return kernel_btf
                        .kfunc_pointer_arg_ref_family(kfunc, release_arg_idx)
                        .map(ref_kind_from_btf_family);
                }

                let mut candidates: Vec<(usize, Option<KfuncRefKind>, bool, bool)> = Vec::new();
                for arg_idx in 0..5 {
                    candidates.push((
                        arg_idx,
                        kernel_btf
                            .kfunc_pointer_arg_ref_family(kfunc, arg_idx)
                            .map(ref_kind_from_btf_family),
                        kernel_btf.kfunc_pointer_arg_is_named_in(kfunc, arg_idx),
                        kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx),
                    ));
                }
                if let Some(kind) = infer_unique_release_kind(&candidates) {
                    return Some(kind);
                }

                return kernel_btf
                    .kfunc_pointer_arg_ref_family(kfunc, 0)
                    .map(ref_kind_from_btf_family);
            }
            None
        }
    }
}

fn infer_unique_release_kind(
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool)],
) -> Option<KfuncRefKind> {
    let mut selected: Option<KfuncRefKind> = None;
    for (_, kind, _, _) in candidates {
        let Some(kind) = kind else {
            continue;
        };
        if let Some(existing) = selected {
            if existing != *kind {
                return None;
            }
        } else {
            selected = Some(*kind);
        }
    }
    selected
}

fn infer_release_arg_from_named_inputs(
    expected_kind: KfuncRefKind,
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool)],
) -> Option<usize> {
    let select_unique = |prefer_non_const: bool| {
        let mut matches = candidates
            .iter()
            .filter_map(|(arg_idx, kind, named_in, is_const)| {
                if *named_in && *kind == Some(expected_kind) && (!prefer_non_const || !*is_const) {
                    Some(*arg_idx)
                } else {
                    None
                }
            });
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    };
    if let Some(idx) = select_unique(true) {
        return Some(idx);
    }
    select_unique(false)
}

fn infer_unique_release_arg_from_kind(
    expected_kind: KfuncRefKind,
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool)],
) -> Option<usize> {
    let select_unique = |prefer_non_const: bool| {
        let mut matches = candidates
            .iter()
            .filter_map(|(arg_idx, kind, _, is_const)| {
                if *kind == Some(expected_kind) && (!prefer_non_const || !*is_const) {
                    Some(*arg_idx)
                } else {
                    None
                }
            });
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    };
    if let Some(idx) = select_unique(true) {
        return Some(idx);
    }
    select_unique(false)
}

pub fn kfunc_release_ref_arg_index(kfunc: &str) -> Option<usize> {
    match kfunc {
        "bpf_list_push_front_impl" | "bpf_list_push_back_impl" | "bpf_rbtree_add_impl" => Some(1),
        _ if kfunc_release_ref_kind(kfunc).is_some() => {
            if KfuncSignature::for_name(kfunc).is_none() {
                let kernel_btf = KernelBtf::get();
                if let Some(arg_idx) = kernel_btf.kfunc_release_ref_arg_index(kfunc) {
                    return Some(arg_idx);
                }
                if let Some(expected_kind) = kfunc_release_ref_kind(kfunc) {
                    let mut candidates: Vec<(usize, Option<KfuncRefKind>, bool, bool)> = Vec::new();
                    for arg_idx in 0..5 {
                        candidates.push((
                            arg_idx,
                            kernel_btf
                                .kfunc_pointer_arg_ref_family(kfunc, arg_idx)
                                .map(ref_kind_from_btf_family),
                            kernel_btf.kfunc_pointer_arg_is_named_in(kfunc, arg_idx),
                            kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx),
                        ));
                    }
                    if let Some(arg_idx) =
                        infer_release_arg_from_named_inputs(expected_kind, &candidates)
                    {
                        return Some(arg_idx);
                    }
                    if let Some(arg_idx) =
                        infer_unique_release_arg_from_kind(expected_kind, &candidates)
                    {
                        return Some(arg_idx);
                    }
                }
                return Some(0);
            }
            Some(0)
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
    if KfuncSignature::for_name(kfunc).is_none() {
        return KernelBtf::get()
            .kfunc_pointer_arg_ref_family(kfunc, arg_idx)
            .map(ref_kind_from_btf_family);
    }
    None
}

pub fn kfunc_pointer_arg_requires_kernel(kfunc: &str, arg_idx: usize) -> bool {
    if kfunc_pointer_arg_ref_kind(kfunc, arg_idx).is_some() {
        return true;
    }
    if matches!(
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
    ) {
        return true;
    }
    if let Some(rule) = kfunc_semantics(kfunc)
        .ptr_arg_rules
        .iter()
        .find(|rule| rule.arg_idx == arg_idx)
        && rule.allowed.allow_kernel
        && !rule.allowed.allow_stack
        && !rule.allowed.allow_map
        && !rule.allowed.allow_user
    {
        return true;
    }
    if KfuncSignature::for_name(kfunc).is_some() {
        return false;
    }
    KernelBtf::get().kfunc_pointer_arg_requires_kernel(kfunc, arg_idx)
}

pub fn kfunc_pointer_arg_requires_user(kfunc: &str, arg_idx: usize) -> bool {
    if let Some(rule) = kfunc_semantics(kfunc)
        .ptr_arg_rules
        .iter()
        .find(|rule| rule.arg_idx == arg_idx)
        && rule.allowed.allow_user
        && !rule.allowed.allow_stack
        && !rule.allowed.allow_map
        && !rule.allowed.allow_kernel
    {
        return true;
    }
    KernelBtf::get().kfunc_pointer_arg_requires_user(kfunc, arg_idx)
}

pub fn kfunc_pointer_arg_requires_stack(kfunc: &str, arg_idx: usize) -> bool {
    if matches!(
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
    ) {
        return true;
    }
    if KfuncSignature::for_name(kfunc).is_some() {
        return false;
    }
    KernelBtf::get().kfunc_pointer_arg_requires_stack(kfunc, arg_idx)
}

fn is_writable_named_out_hint(is_named_out: bool, is_const: bool) -> bool {
    is_named_out && !is_const
}

pub fn kfunc_pointer_arg_requires_stack_slot_base(kfunc: &str, arg_idx: usize) -> bool {
    if matches!(
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
    ) {
        return true;
    }
    if KfuncSignature::for_name(kfunc).is_some() {
        return false;
    }
    let kernel_btf = KernelBtf::get();
    kernel_btf.kfunc_pointer_arg_requires_stack_slot_base(kfunc, arg_idx)
        || is_writable_named_out_hint(
            kernel_btf.kfunc_pointer_arg_is_named_out(kfunc, arg_idx),
            kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx),
        )
}

pub fn kfunc_pointer_arg_requires_stack_or_map(kfunc: &str, arg_idx: usize) -> bool {
    if KfuncSignature::for_name(kfunc).is_some() {
        return false;
    }

    let kernel_btf = KernelBtf::get();
    if !is_writable_named_out_hint(
        kernel_btf.kfunc_pointer_arg_is_named_out(kfunc, arg_idx),
        kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx),
    ) {
        return false;
    }
    if kernel_btf.kfunc_pointer_arg_requires_stack(kfunc, arg_idx)
        || kernel_btf.kfunc_pointer_arg_requires_kernel(kfunc, arg_idx)
        || kernel_btf.kfunc_pointer_arg_requires_user(kfunc, arg_idx)
        || kernel_btf
            .kfunc_pointer_arg_ref_family(kfunc, arg_idx)
            .is_some()
    {
        return false;
    }

    true
}

pub fn kfunc_pointer_arg_min_access_size(kfunc: &str, arg_idx: usize) -> Option<usize> {
    if kfunc_pointer_arg_requires_stack_or_map(kfunc, arg_idx) {
        Some(1)
    } else {
        None
    }
}

fn iter_lifecycle_op_from_kfunc_name(kfunc: &str) -> Option<KfuncIterLifecycleOp> {
    if kfunc.ends_with("_new") {
        return Some(KfuncIterLifecycleOp::New);
    }
    if kfunc.ends_with("_next") {
        return Some(KfuncIterLifecycleOp::Next);
    }
    if kfunc.ends_with("_destroy") {
        return Some(KfuncIterLifecycleOp::Destroy);
    }
    None
}

fn iter_family_from_stack_object_type_name(type_name: &str) -> Option<KfuncIterFamily> {
    match type_name {
        "bpf_iter_task_vma" => Some(KfuncIterFamily::TaskVma),
        "bpf_iter_task" => Some(KfuncIterFamily::Task),
        "bpf_iter_scx_dsq" => Some(KfuncIterFamily::ScxDsq),
        "bpf_iter_num" => Some(KfuncIterFamily::Num),
        "bpf_iter_bits" => Some(KfuncIterFamily::Bits),
        "bpf_iter_css" => Some(KfuncIterFamily::Css),
        "bpf_iter_css_task" => Some(KfuncIterFamily::CssTask),
        "bpf_iter_dmabuf" => Some(KfuncIterFamily::Dmabuf),
        "bpf_iter_kmem_cache" => Some(KfuncIterFamily::KmemCache),
        _ => None,
    }
}

fn is_dynptr_stack_object_type_name(type_name: &str) -> bool {
    type_name == "bpf_dynptr" || type_name.starts_with("bpf_dynptr_")
}

fn is_special_stack_object_type_name(type_name: &str) -> bool {
    iter_family_from_stack_object_type_name(type_name).is_some()
        || is_dynptr_stack_object_type_name(type_name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnknownStackObjectArgInfo {
    arg_idx: usize,
    type_name: String,
    named_out: bool,
    named_in: bool,
}

pub fn kfunc_unknown_iter_lifecycle(kfunc: &str) -> Option<KfuncUnknownIterLifecycle> {
    if KfuncSignature::for_name(kfunc).is_some() {
        return None;
    }
    let op = iter_lifecycle_op_from_kfunc_name(kfunc)?;
    let kernel_btf = KernelBtf::get();
    let mut match_hint: Option<KfuncUnknownIterLifecycle> = None;
    for arg_idx in 0..5 {
        let Some(type_name) = kernel_btf.kfunc_pointer_arg_stack_object_type_name(kfunc, arg_idx)
        else {
            continue;
        };
        let Some(family) = iter_family_from_stack_object_type_name(&type_name) else {
            continue;
        };
        if match_hint.is_some() {
            // Ambiguous stack-object args: do not infer lifecycle semantics.
            return None;
        }
        match_hint = Some(KfuncUnknownIterLifecycle {
            family,
            op,
            arg_idx,
        });
    }
    match_hint
}

pub fn kfunc_unknown_dynptr_args(kfunc: &str) -> Vec<KfuncUnknownDynptrArg> {
    if KfuncSignature::for_name(kfunc).is_some() {
        return Vec::new();
    }
    let kernel_btf = KernelBtf::get();
    let mut args = Vec::new();
    for arg_idx in 0..5 {
        let Some(type_name) = kernel_btf.kfunc_pointer_arg_stack_object_type_name(kfunc, arg_idx)
        else {
            continue;
        };
        if !is_dynptr_stack_object_type_name(&type_name) {
            continue;
        }
        let role = if is_writable_named_out_hint(
            kernel_btf.kfunc_pointer_arg_is_named_out(kfunc, arg_idx),
            kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx),
        ) {
            KfuncUnknownDynptrArgRole::Out
        } else {
            KfuncUnknownDynptrArgRole::In
        };
        args.push(KfuncUnknownDynptrArg { arg_idx, role });
    }
    args
}

fn infer_unknown_dynptr_copy_args(
    args: &[KfuncUnknownDynptrArg],
    named_in_arg_indices: &[usize],
    const_arg_indices: &[usize],
    move_semantics: bool,
) -> Vec<(usize, usize)> {
    if args.len() < 2 {
        return Vec::new();
    }

    let all_out_args: Vec<usize> = args
        .iter()
        .filter(|arg| arg.role == KfuncUnknownDynptrArgRole::Out)
        .map(|arg| arg.arg_idx)
        .collect();
    let has_out_hints = !all_out_args.is_empty();
    let mut out_args: Vec<usize> = all_out_args
        .iter()
        .copied()
        .filter(|arg_idx| !const_arg_indices.contains(arg_idx))
        .collect();
    if out_args.is_empty() && has_out_hints {
        if move_semantics {
            // Move semantics require a writable destination.
            return Vec::new();
        }
        out_args = all_out_args;
    }
    let in_args: Vec<usize> = args
        .iter()
        .filter(|arg| arg.role == KfuncUnknownDynptrArgRole::In)
        .map(|arg| arg.arg_idx)
        .collect();
    let all_args: Vec<usize> = args.iter().map(|arg| arg.arg_idx).collect();
    if in_args.is_empty() && all_args.is_empty() {
        return Vec::new();
    }

    let named_in_matches: Vec<usize> = all_args
        .iter()
        .copied()
        .filter(|arg_idx| named_in_arg_indices.contains(arg_idx))
        .collect();
    let const_in_matches_all: Vec<usize> = all_args
        .iter()
        .copied()
        .filter(|arg_idx| const_arg_indices.contains(arg_idx))
        .collect();
    if out_args.is_empty() {
        // Conservative unnamed fallback: only infer when exactly two args exist.
        if all_args.len() != 2 {
            return Vec::new();
        }
        let src_arg_idx = if named_in_matches.len() == 1 {
            named_in_matches[0]
        } else if named_in_matches.is_empty() && const_in_matches_all.len() == 1 {
            const_in_matches_all[0]
        } else if named_in_matches.is_empty() {
            all_args[0]
        } else {
            return Vec::new();
        };
        let dst_arg_idx = if all_args[0] == src_arg_idx {
            all_args[1]
        } else {
            all_args[0]
        };
        if move_semantics && const_arg_indices.contains(&dst_arg_idx) {
            // Move semantics require a writable destination.
            return Vec::new();
        }
        return vec![(src_arg_idx, dst_arg_idx)];
    }

    if in_args.is_empty() {
        return Vec::new();
    }

    let named_in_matches: Vec<usize> = in_args
        .iter()
        .copied()
        .filter(|arg_idx| named_in_arg_indices.contains(arg_idx))
        .collect();
    let const_in_matches: Vec<usize> = in_args
        .iter()
        .copied()
        .filter(|arg_idx| const_arg_indices.contains(arg_idx))
        .collect();
    let src_arg_idx = if named_in_matches.len() == 1 {
        named_in_matches[0]
    } else if named_in_matches.is_empty() && const_in_matches.len() == 1 {
        const_in_matches[0]
    } else if named_in_matches.is_empty() && const_in_matches.is_empty() && in_args.len() == 1 {
        in_args[0]
    } else {
        return Vec::new();
    };
    if move_semantics && out_args.len() != 1 {
        return Vec::new();
    }
    out_args
        .into_iter()
        .map(|dst_arg_idx| (src_arg_idx, dst_arg_idx))
        .collect()
}

fn unknown_transfer_move_semantics_from_kfunc_name(kfunc: &str) -> Option<bool> {
    let lower = kfunc.to_ascii_lowercase();
    let has_move_like = lower.contains("_move");
    let has_copy_like = lower.contains("_copy")
        || lower.contains("_clone")
        || lower.contains("_assign")
        || lower.contains("_from_")
        || (lower.contains("_to_") && !has_move_like)
        || lower.contains("_dup");
    if !has_copy_like && !has_move_like {
        return None;
    }
    Some(has_move_like && !has_copy_like)
}

pub fn kfunc_unknown_dynptr_copy(kfunc: &str) -> Vec<KfuncUnknownDynptrCopy> {
    if KfuncSignature::for_name(kfunc).is_some() {
        return Vec::new();
    }
    let Some(move_semantics) = unknown_transfer_move_semantics_from_kfunc_name(kfunc) else {
        return Vec::new();
    };
    let kernel_btf = KernelBtf::get();
    let args = kfunc_unknown_dynptr_args(kfunc);
    let named_in_args: Vec<usize> = args
        .iter()
        .filter(|arg| kernel_btf.kfunc_pointer_arg_is_named_in(kfunc, arg.arg_idx))
        .map(|arg| arg.arg_idx)
        .collect();
    let const_args: Vec<usize> = args
        .iter()
        .filter(|arg| kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg.arg_idx))
        .map(|arg| arg.arg_idx)
        .collect();
    infer_unknown_dynptr_copy_args(&args, &named_in_args, &const_args, move_semantics)
        .into_iter()
        .map(|(src_arg_idx, dst_arg_idx)| KfuncUnknownDynptrCopy {
            src_arg_idx,
            dst_arg_idx,
            move_semantics,
        })
        .collect()
}

fn unknown_stack_object_lifecycle_op_from_kfunc_name(
    kfunc: &str,
) -> Option<KfuncUnknownStackObjectLifecycleOp> {
    let lower = kfunc.to_ascii_lowercase();
    if lower.ends_with("_init")
        || lower.ends_with("_new")
        || lower.ends_with("_create")
        || lower.ends_with("_alloc")
        || lower.contains("_init_")
        || lower.contains("_create_")
        || lower.contains("_alloc_")
    {
        return Some(KfuncUnknownStackObjectLifecycleOp::Init);
    }
    if lower.ends_with("_destroy")
        || lower.contains("_destroy_")
        || lower.ends_with("_release")
        || lower.contains("_release_")
        || lower.ends_with("_drop")
        || lower.contains("_drop_")
        || lower.ends_with("_cleanup")
        || lower.contains("_cleanup_")
        || lower.ends_with("_deinit")
        || lower.ends_with("_fini")
    {
        return Some(KfuncUnknownStackObjectLifecycleOp::Destroy);
    }
    None
}

fn unknown_stack_object_args(kfunc: &str) -> Vec<UnknownStackObjectArgInfo> {
    if KfuncSignature::for_name(kfunc).is_some() {
        return Vec::new();
    }
    let kernel_btf = KernelBtf::get();
    let mut args = Vec::new();
    for arg_idx in 0..5 {
        let Some(type_name) = kernel_btf.kfunc_pointer_arg_stack_object_type_name(kfunc, arg_idx)
        else {
            continue;
        };
        if is_special_stack_object_type_name(&type_name) {
            continue;
        }
        args.push(UnknownStackObjectArgInfo {
            arg_idx,
            type_name,
            named_out: is_writable_named_out_hint(
                kernel_btf.kfunc_pointer_arg_is_named_out(kfunc, arg_idx),
                kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx),
            ),
            named_in: kernel_btf.kfunc_pointer_arg_is_named_in(kfunc, arg_idx),
        });
    }
    args
}

fn infer_unknown_stack_object_copy_args_for_type<'a>(
    args: &[&'a UnknownStackObjectArgInfo],
    const_arg_indices: &BTreeSet<usize>,
    move_semantics: bool,
) -> Vec<(&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo)> {
    if args.len() < 2 {
        return Vec::new();
    }

    let infer_from_candidates =
        |candidates: Vec<(&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo)>| {
            if candidates.is_empty() {
                return Vec::new();
            }

            let mut source_candidates = BTreeSet::new();
            for (src, _) in &candidates {
                source_candidates.insert(src.arg_idx);
            }
            if source_candidates.len() != 1 {
                return Vec::new();
            }
            let src_arg_idx = source_candidates
                .iter()
                .next()
                .copied()
                .expect("source set is known non-empty");

            let mut all_destination_candidates: BTreeMap<
                usize,
                (&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo),
            > = BTreeMap::new();
            for (src, dst) in candidates
                .into_iter()
                .filter(|(src, _)| src.arg_idx == src_arg_idx)
            {
                all_destination_candidates.insert(dst.arg_idx, (src, dst));
            }
            if all_destination_candidates.is_empty() {
                return Vec::new();
            }

            let mut destination_candidates: BTreeMap<
                usize,
                (&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo),
            > = all_destination_candidates
                .iter()
                .filter_map(|(dst_arg_idx, pair)| {
                    if const_arg_indices.contains(dst_arg_idx) {
                        None
                    } else {
                        Some((*dst_arg_idx, *pair))
                    }
                })
                .collect();
            if destination_candidates.is_empty() {
                if move_semantics {
                    // Move semantics require a writable destination.
                    return Vec::new();
                }
                destination_candidates = all_destination_candidates;
            }

            if move_semantics && destination_candidates.len() != 1 {
                return Vec::new();
            }
            destination_candidates.into_values().collect()
        };

    let mut candidates: Vec<(&UnknownStackObjectArgInfo, &UnknownStackObjectArgInfo)> = Vec::new();
    for src in args.iter().copied().filter(|arg| arg.named_in) {
        for dst in args.iter().copied().filter(|arg| arg.named_out) {
            if src.arg_idx == dst.arg_idx || src.type_name != dst.type_name {
                continue;
            }
            candidates.push((src, dst));
        }
    }
    let inferred = infer_from_candidates(candidates);
    if !inferred.is_empty() {
        return inferred;
    }

    let mut candidates: Vec<(&UnknownStackObjectArgInfo, &UnknownStackObjectArgInfo)> = Vec::new();
    for src in args.iter().copied().filter(|arg| !arg.named_out) {
        for dst in args.iter().copied().filter(|arg| arg.named_out) {
            if src.arg_idx == dst.arg_idx || src.type_name != dst.type_name {
                continue;
            }
            candidates.push((src, dst));
        }
    }

    let inferred = infer_from_candidates(candidates);
    if !inferred.is_empty() {
        return inferred;
    }

    // Conservative unnamed fallback: if no destination hint exists and exactly
    // two same-type args are present, treat one as src and the other as dst.
    if args.len() == 2 && args.iter().all(|arg| !arg.named_out) {
        let named_in: Vec<&UnknownStackObjectArgInfo> =
            args.iter().copied().filter(|arg| arg.named_in).collect();
        let src = if named_in.len() == 1 {
            named_in[0]
        } else if named_in.is_empty() {
            args[0]
        } else {
            return Vec::new();
        };
        let dst = if args[0].arg_idx == src.arg_idx {
            args[1]
        } else {
            args[0]
        };
        if move_semantics && const_arg_indices.contains(&dst.arg_idx) {
            // Move semantics require a writable destination.
            return Vec::new();
        }
        return vec![(src, dst)];
    }

    Vec::new()
}

fn infer_unknown_stack_object_copy_args_from_const_hints<'a>(
    args: &[&'a UnknownStackObjectArgInfo],
    const_arg_indices: &BTreeSet<usize>,
    move_semantics: bool,
) -> Vec<(&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo)> {
    if args.len() < 2 {
        return Vec::new();
    }

    let const_sources: Vec<&UnknownStackObjectArgInfo> = args
        .iter()
        .copied()
        .filter(|arg| const_arg_indices.contains(&arg.arg_idx))
        .collect();
    if const_sources.len() != 1 {
        return Vec::new();
    }
    let src = const_sources[0];

    let mut dsts: BTreeMap<usize, &UnknownStackObjectArgInfo> = BTreeMap::new();
    for dst in args
        .iter()
        .copied()
        .filter(|arg| arg.arg_idx != src.arg_idx && !const_arg_indices.contains(&arg.arg_idx))
    {
        dsts.insert(dst.arg_idx, dst);
    }
    if dsts.is_empty() {
        return Vec::new();
    }
    if move_semantics && dsts.len() != 1 {
        return Vec::new();
    }
    dsts.into_values().map(|dst| (src, dst)).collect()
}

#[cfg(test)]
fn infer_unknown_stack_object_copy_args<'a>(
    args: &'a [UnknownStackObjectArgInfo],
    move_semantics: bool,
) -> Vec<(&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo)> {
    if args.len() < 2 {
        return Vec::new();
    }

    let mut args_by_type: BTreeMap<&str, Vec<&UnknownStackObjectArgInfo>> = BTreeMap::new();
    for arg in args {
        args_by_type
            .entry(arg.type_name.as_str())
            .or_default()
            .push(arg);
    }

    let mut copies = Vec::new();
    for type_args in args_by_type.values() {
        copies.extend(infer_unknown_stack_object_copy_args_for_type(
            type_args,
            &BTreeSet::new(),
            move_semantics,
        ));
    }
    copies
}

fn infer_unknown_stack_object_lifecycle_arg<'a>(
    args: &'a [UnknownStackObjectArgInfo],
    op: KfuncUnknownStackObjectLifecycleOp,
    const_arg_indices: &BTreeSet<usize>,
) -> Option<&'a UnknownStackObjectArgInfo> {
    if args.is_empty() {
        return None;
    }
    if args.len() == 1 {
        let arg = args.first()?;
        if matches!(op, KfuncUnknownStackObjectLifecycleOp::Init)
            && const_arg_indices.contains(&arg.arg_idx)
        {
            return None;
        }
        return Some(arg);
    }

    let mut candidates: Vec<&UnknownStackObjectArgInfo> = match op {
        KfuncUnknownStackObjectLifecycleOp::Init => {
            args.iter().filter(|arg| arg.named_out).collect()
        }
        KfuncUnknownStackObjectLifecycleOp::Destroy => args
            .iter()
            .filter(|arg| !arg.named_out && arg.named_in)
            .collect(),
    };

    if matches!(op, KfuncUnknownStackObjectLifecycleOp::Init) {
        let writable_candidates: Vec<&UnknownStackObjectArgInfo> = candidates
            .iter()
            .copied()
            .filter(|arg| !const_arg_indices.contains(&arg.arg_idx))
            .collect();
        if writable_candidates.len() == 1 {
            return writable_candidates.first().copied();
        }
        if !writable_candidates.is_empty() {
            candidates = writable_candidates;
        }
    }

    if candidates.len() == 1 {
        let arg = candidates.first().copied()?;
        if matches!(op, KfuncUnknownStackObjectLifecycleOp::Init)
            && const_arg_indices.contains(&arg.arg_idx)
        {
            return None;
        }
        return Some(arg);
    }

    if matches!(op, KfuncUnknownStackObjectLifecycleOp::Destroy) {
        candidates = args.iter().filter(|arg| !arg.named_out).collect();
        if candidates.len() == 1 {
            return candidates.first().copied();
        }
    }

    None
}

fn infer_unknown_stack_object_lifecycle_arg_from_const_hints<'a>(
    args: &'a [UnknownStackObjectArgInfo],
    op: KfuncUnknownStackObjectLifecycleOp,
    const_arg_indices: &BTreeSet<usize>,
) -> Option<&'a UnknownStackObjectArgInfo> {
    if args.is_empty() {
        return None;
    }

    let mut candidates = match op {
        KfuncUnknownStackObjectLifecycleOp::Init => args
            .iter()
            .filter(|arg| !const_arg_indices.contains(&arg.arg_idx))
            .collect::<Vec<_>>(),
        KfuncUnknownStackObjectLifecycleOp::Destroy => args
            .iter()
            .filter(|arg| !arg.named_out && const_arg_indices.contains(&arg.arg_idx))
            .collect::<Vec<_>>(),
    };
    if candidates.len() == 1 {
        return candidates.first().copied();
    }

    if matches!(op, KfuncUnknownStackObjectLifecycleOp::Destroy) {
        candidates = args.iter().filter(|arg| !arg.named_out).collect();
        if candidates.len() == 1 {
            return candidates.first().copied();
        }
    }

    None
}

pub fn kfunc_unknown_stack_object_lifecycle(
    kfunc: &str,
) -> Option<KfuncUnknownStackObjectLifecycle> {
    let op = unknown_stack_object_lifecycle_op_from_kfunc_name(kfunc)?;
    let args = unknown_stack_object_args(kfunc);
    let kernel_btf = KernelBtf::get();
    let const_args: BTreeSet<usize> = args
        .iter()
        .filter(|arg| kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg.arg_idx))
        .map(|arg| arg.arg_idx)
        .collect();
    let arg = infer_unknown_stack_object_lifecycle_arg(&args, op, &const_args).or_else(|| {
        infer_unknown_stack_object_lifecycle_arg_from_const_hints(&args, op, &const_args)
    })?;
    Some(KfuncUnknownStackObjectLifecycle {
        type_name: arg.type_name.clone(),
        op,
        arg_idx: arg.arg_idx,
    })
}

pub fn kfunc_unknown_stack_object_copy(kfunc: &str) -> Vec<KfuncUnknownStackObjectCopy> {
    if KfuncSignature::for_name(kfunc).is_some() {
        return Vec::new();
    }
    let Some(move_semantics) = unknown_transfer_move_semantics_from_kfunc_name(kfunc) else {
        return Vec::new();
    };
    let args = unknown_stack_object_args(kfunc);
    let kernel_btf = KernelBtf::get();
    let const_pointer_args: BTreeSet<usize> = args
        .iter()
        .filter(|arg| kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg.arg_idx))
        .map(|arg| arg.arg_idx)
        .collect();
    let mut args_by_identity: BTreeMap<(Option<u32>, &str), Vec<&UnknownStackObjectArgInfo>> =
        BTreeMap::new();
    for arg in &args {
        let identity = (
            kernel_btf.kfunc_pointer_arg_stack_object_type_id(kfunc, arg.arg_idx),
            arg.type_name.as_str(),
        );
        args_by_identity.entry(identity).or_default().push(arg);
    }

    let mut copies = Vec::new();
    for type_args in args_by_identity.values() {
        let mut inferred = infer_unknown_stack_object_copy_args_for_type(
            type_args,
            &const_pointer_args,
            move_semantics,
        );
        if inferred.is_empty() {
            inferred = infer_unknown_stack_object_copy_args_from_const_hints(
                type_args,
                &const_pointer_args,
                move_semantics,
            );
        }
        for (src, dst) in inferred {
            copies.push(KfuncUnknownStackObjectCopy {
                type_name: src.type_name.clone(),
                src_arg_idx: src.arg_idx,
                dst_arg_idx: dst.arg_idx,
                move_semantics,
            });
        }
    }
    copies
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

pub fn kfunc_scalar_arg_requires_known_const(kfunc: &str, arg_idx: usize) -> bool {
    matches!(
        (kfunc, arg_idx),
        ("bpf_dynptr_slice", 3) | ("bpf_dynptr_slice_rdwr", 3)
    ) || KernelBtf::get().kfunc_scalar_arg_requires_known_const(kfunc, arg_idx)
}

pub fn kfunc_scalar_arg_requires_positive(kfunc: &str, arg_idx: usize) -> bool {
    kfunc_semantics(kfunc).positive_size_args.contains(&arg_idx)
        || KernelBtf::get().kfunc_scalar_arg_requires_positive(kfunc, arg_idx)
}

pub fn kfunc_pointer_arg_size_from_scalar(kfunc: &str, arg_idx: usize) -> Option<usize> {
    if let Some(rule) = kfunc_semantics(kfunc)
        .ptr_arg_rules
        .iter()
        .find(|rule| rule.arg_idx == arg_idx)
    {
        return rule.size_from_arg;
    }
    KernelBtf::get().kfunc_pointer_arg_size_arg(kfunc, arg_idx)
}

pub fn kfunc_pointer_arg_fixed_size(kfunc: &str, arg_idx: usize) -> Option<usize> {
    if let Some(rule) = kfunc_semantics(kfunc)
        .ptr_arg_rules
        .iter()
        .find(|rule| rule.arg_idx == arg_idx)
    {
        return rule.fixed_size;
    }
    if KfuncSignature::for_name(kfunc).is_some() {
        return None;
    }
    KernelBtf::get().kfunc_pointer_arg_fixed_size(kfunc, arg_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iter_lifecycle_op_from_kfunc_name() {
        assert_eq!(
            iter_lifecycle_op_from_kfunc_name("bpf_iter_task_new"),
            Some(KfuncIterLifecycleOp::New)
        );
        assert_eq!(
            iter_lifecycle_op_from_kfunc_name("bpf_iter_task_next"),
            Some(KfuncIterLifecycleOp::Next)
        );
        assert_eq!(
            iter_lifecycle_op_from_kfunc_name("bpf_iter_task_destroy"),
            Some(KfuncIterLifecycleOp::Destroy)
        );
        assert_eq!(iter_lifecycle_op_from_kfunc_name("bpf_task_from_pid"), None);
    }

    #[test]
    fn test_iter_family_from_stack_object_type_name() {
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_task_vma"),
            Some(KfuncIterFamily::TaskVma)
        );
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_task"),
            Some(KfuncIterFamily::Task)
        );
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_scx_dsq"),
            Some(KfuncIterFamily::ScxDsq)
        );
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_num"),
            Some(KfuncIterFamily::Num)
        );
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_bits"),
            Some(KfuncIterFamily::Bits)
        );
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_css"),
            Some(KfuncIterFamily::Css)
        );
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_css_task"),
            Some(KfuncIterFamily::CssTask)
        );
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_dmabuf"),
            Some(KfuncIterFamily::Dmabuf)
        );
        assert_eq!(
            iter_family_from_stack_object_type_name("bpf_iter_kmem_cache"),
            Some(KfuncIterFamily::KmemCache)
        );
        assert_eq!(iter_family_from_stack_object_type_name("bpf_dynptr"), None);
    }

    #[test]
    fn test_is_dynptr_stack_object_type_name() {
        assert!(is_dynptr_stack_object_type_name("bpf_dynptr"));
        assert!(is_dynptr_stack_object_type_name("bpf_dynptr_kern"));
        assert!(!is_dynptr_stack_object_type_name("bpf_iter_task"));
    }

    #[test]
    fn test_is_writable_named_out_hint() {
        assert!(
            is_writable_named_out_hint(true, false),
            "non-const named-out args should be treated as writable out hints"
        );
        assert!(
            !is_writable_named_out_hint(true, true),
            "const named-out args should not be treated as writable out hints"
        );
        assert!(
            !is_writable_named_out_hint(false, false),
            "non-out args should not be treated as out hints"
        );
    }

    #[test]
    fn test_unknown_stack_object_lifecycle_op_from_kfunc_name() {
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_init"),
            Some(KfuncUnknownStackObjectLifecycleOp::Init)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_new"),
            Some(KfuncUnknownStackObjectLifecycleOp::Init)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_create"),
            Some(KfuncUnknownStackObjectLifecycleOp::Init)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_alloc"),
            Some(KfuncUnknownStackObjectLifecycleOp::Init)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_destroy"),
            Some(KfuncUnknownStackObjectLifecycleOp::Destroy)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_release"),
            Some(KfuncUnknownStackObjectLifecycleOp::Destroy)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_drop"),
            Some(KfuncUnknownStackObjectLifecycleOp::Destroy)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_cleanup"),
            Some(KfuncUnknownStackObjectLifecycleOp::Destroy)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_deinit"),
            Some(KfuncUnknownStackObjectLifecycleOp::Destroy)
        );
        assert_eq!(
            unknown_stack_object_lifecycle_op_from_kfunc_name("foo_obj_query"),
            None
        );
    }

    #[test]
    fn test_should_infer_unknown_acquire_ref_name_hints() {
        assert!(should_infer_unknown_acquire_ref(
            "foo_task_acquire",
            KfuncRefKind::Task,
            true,
            false
        ));
        assert!(should_infer_unknown_acquire_ref(
            "bpf_get_foo_task",
            KfuncRefKind::Task,
            true,
            false
        ));
        assert!(should_infer_unknown_acquire_ref(
            "foo_get_task",
            KfuncRefKind::Task,
            true,
            false
        ));
        assert!(should_infer_unknown_acquire_ref(
            "foo_task_get",
            KfuncRefKind::Task,
            true,
            false
        ));
        assert!(should_infer_unknown_acquire_ref(
            "foo_task_dup",
            KfuncRefKind::Task,
            true,
            false
        ));
        assert!(should_infer_unknown_acquire_ref(
            "foo_task_clone",
            KfuncRefKind::Task,
            true,
            false
        ));
        assert!(should_infer_unknown_acquire_ref(
            "foo_lookup_sock",
            KfuncRefKind::Socket,
            true,
            false
        ));
    }

    #[test]
    fn test_should_infer_unknown_acquire_ref_without_same_family_args() {
        assert!(should_infer_unknown_acquire_ref(
            "foo_plain_name",
            KfuncRefKind::Task,
            false,
            false
        ));
    }

    #[test]
    fn test_should_infer_unknown_acquire_ref_with_const_only_same_family_args() {
        assert!(should_infer_unknown_acquire_ref(
            "foo_plain_name",
            KfuncRefKind::Task,
            true,
            true
        ));
    }

    #[test]
    fn test_should_not_infer_unknown_acquire_ref_without_hints_when_same_family_arg_exists() {
        assert!(!should_infer_unknown_acquire_ref(
            "foo_plain_name",
            KfuncRefKind::Task,
            true,
            false
        ));
    }

    #[test]
    fn test_unknown_transfer_move_semantics_from_kfunc_name() {
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_copy"),
            Some(false)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_clone"),
            Some(false)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_assign"),
            Some(false)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_new_from_template"),
            Some(false)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_copy_to_buf"),
            Some(false)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_dup"),
            Some(false)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_move"),
            Some(true)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_move_to_slot"),
            Some(true)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_move_copy"),
            Some(false)
        );
        assert_eq!(
            unknown_transfer_move_semantics_from_kfunc_name("foo_obj_swap"),
            None
        );
    }

    #[test]
    fn test_infer_unique_release_kind_selects_unique_kind() {
        let candidates = vec![
            (0usize, Some(KfuncRefKind::Task), false, false),
            (1usize, None, false, false),
            (2usize, Some(KfuncRefKind::Task), true, true),
        ];
        assert_eq!(
            infer_unique_release_kind(&candidates),
            Some(KfuncRefKind::Task)
        );
    }

    #[test]
    fn test_infer_unique_release_kind_rejects_mixed_kinds() {
        let candidates = vec![
            (0usize, Some(KfuncRefKind::Task), false, false),
            (1usize, Some(KfuncRefKind::Cgroup), false, false),
        ];
        assert_eq!(infer_unique_release_kind(&candidates), None);
    }

    #[test]
    fn test_infer_unique_release_kind_requires_ref_family_candidates() {
        let candidates = vec![(0usize, None, false, false), (1usize, None, true, true)];
        assert_eq!(infer_unique_release_kind(&candidates), None);
    }

    #[test]
    fn test_infer_release_arg_from_named_inputs_selects_unique_match() {
        let candidates = vec![
            (0usize, Some(KfuncRefKind::Task), false, false),
            (1usize, Some(KfuncRefKind::Task), true, false),
            (2usize, Some(KfuncRefKind::Cgroup), true, false),
        ];
        assert_eq!(
            infer_release_arg_from_named_inputs(KfuncRefKind::Task, &candidates),
            Some(1)
        );
    }

    #[test]
    fn test_infer_release_arg_from_named_inputs_rejects_ambiguous_match() {
        let candidates = vec![
            (0usize, Some(KfuncRefKind::Task), true, false),
            (1usize, Some(KfuncRefKind::Task), true, false),
        ];
        assert_eq!(
            infer_release_arg_from_named_inputs(KfuncRefKind::Task, &candidates),
            None
        );
    }

    #[test]
    fn test_infer_release_arg_from_named_inputs_requires_kind_match() {
        let candidates = vec![(0usize, Some(KfuncRefKind::Cgroup), true, false)];
        assert_eq!(
            infer_release_arg_from_named_inputs(KfuncRefKind::Task, &candidates),
            None
        );
    }

    #[test]
    fn test_infer_release_arg_from_named_inputs_prefers_non_const() {
        let candidates = vec![
            (0usize, Some(KfuncRefKind::Task), true, true),
            (1usize, Some(KfuncRefKind::Task), true, false),
        ];
        assert_eq!(
            infer_release_arg_from_named_inputs(KfuncRefKind::Task, &candidates),
            Some(1)
        );
    }

    #[test]
    fn test_infer_unique_release_arg_from_kind_selects_unique_match() {
        let candidates = vec![
            (0usize, Some(KfuncRefKind::Task), false, false),
            (1usize, Some(KfuncRefKind::Cgroup), true, false),
        ];
        assert_eq!(
            infer_unique_release_arg_from_kind(KfuncRefKind::Task, &candidates),
            Some(0)
        );
    }

    #[test]
    fn test_infer_unique_release_arg_from_kind_rejects_ambiguous_match() {
        let candidates = vec![
            (0usize, Some(KfuncRefKind::Task), false, false),
            (1usize, Some(KfuncRefKind::Task), true, false),
        ];
        assert_eq!(
            infer_unique_release_arg_from_kind(KfuncRefKind::Task, &candidates),
            None
        );
    }

    #[test]
    fn test_infer_unique_release_arg_from_kind_requires_kind_match() {
        let candidates = vec![(0usize, Some(KfuncRefKind::Cgroup), false, false)];
        assert_eq!(
            infer_unique_release_arg_from_kind(KfuncRefKind::Task, &candidates),
            None
        );
    }

    #[test]
    fn test_infer_unique_release_arg_from_kind_prefers_non_const() {
        let candidates = vec![
            (0usize, Some(KfuncRefKind::Task), false, true),
            (1usize, Some(KfuncRefKind::Task), false, false),
        ];
        assert_eq!(
            infer_unique_release_arg_from_kind(KfuncRefKind::Task, &candidates),
            Some(1)
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_selects_unique_pair() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_custom".to_string(),
                named_out: true,
                named_in: false,
            },
        ];

        let copies = infer_unknown_stack_object_copy_args(&args, false);
        assert_eq!(copies.len(), 1, "expected one inferred copy pair");
        let (src, dst) = copies[0];
        assert_eq!(src.arg_idx, 0);
        assert_eq!(dst.arg_idx, 1);
        assert_eq!(src.type_name, "bpf_wq");
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_prefers_named_input() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
        ];

        let copies = infer_unknown_stack_object_copy_args(&args, false);
        assert_eq!(copies.len(), 1, "expected one inferred copy pair");
        let (src, dst) = copies[0];
        assert_eq!(src.arg_idx, 1);
        assert_eq!(dst.arg_idx, 2);
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_falls_back_without_out_hints() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];

        let copies = infer_unknown_stack_object_copy_args(&args, false);
        assert_eq!(
            copies.len(),
            1,
            "expected unnamed two-arg fallback inference"
        );
        let (src, dst) = copies[0];
        assert_eq!(src.arg_idx, 0);
        assert_eq!(dst.arg_idx, 1);
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_fallback_prefers_named_input() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
        ];

        let copies = infer_unknown_stack_object_copy_args(&args, false);
        assert_eq!(
            copies.len(),
            1,
            "expected unnamed fallback with named-in source"
        );
        let (src, dst) = copies[0];
        assert_eq!(src.arg_idx, 1);
        assert_eq!(dst.arg_idx, 0);
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_fallback_rejects_ambiguous_named_input() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
        ];

        assert!(
            infer_unknown_stack_object_copy_args(&args, false).is_empty(),
            "unnamed fallback should reject ambiguous named-in source selection"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_allows_multiple_destinations_for_copy() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
        ];

        let copies = infer_unknown_stack_object_copy_args(&args, false);
        assert_eq!(
            copies.len(),
            2,
            "expected one source copied to two destinations"
        );
        assert!(
            copies
                .iter()
                .any(|(src, dst)| src.arg_idx == 0 && dst.arg_idx == 1)
        );
        assert!(
            copies
                .iter()
                .any(|(src, dst)| src.arg_idx == 0 && dst.arg_idx == 2)
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_move_requires_single_destination() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
        ];

        assert!(
            infer_unknown_stack_object_copy_args(&args, true).is_empty(),
            "move semantics should require a single destination slot"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_for_type_prefers_non_const_destination() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
        ];
        let type_args: Vec<&UnknownStackObjectArgInfo> = args.iter().collect();
        let const_args: std::collections::BTreeSet<usize> = [1usize].into_iter().collect();

        let inferred =
            infer_unknown_stack_object_copy_args_for_type(&type_args, &const_args, false);
        assert_eq!(
            inferred.len(),
            1,
            "copy inference should prefer writable destinations when available"
        );
        let (src, dst) = inferred[0];
        assert_eq!(src.arg_idx, 0);
        assert_eq!(dst.arg_idx, 2);
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_for_type_falls_back_to_const_destination() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
        ];
        let type_args: Vec<&UnknownStackObjectArgInfo> = args.iter().collect();
        let const_args: std::collections::BTreeSet<usize> = [1usize].into_iter().collect();

        let inferred =
            infer_unknown_stack_object_copy_args_for_type(&type_args, &const_args, false);
        assert_eq!(
            inferred.len(),
            1,
            "copy inference should still use const destination when no writable alternative exists"
        );
        let (src, dst) = inferred[0];
        assert_eq!(src.arg_idx, 0);
        assert_eq!(dst.arg_idx, 1);
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_for_type_move_requires_writable_destination() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
        ];
        let type_args: Vec<&UnknownStackObjectArgInfo> = args.iter().collect();
        let const_args: std::collections::BTreeSet<usize> = [1usize].into_iter().collect();

        assert!(
            infer_unknown_stack_object_copy_args_for_type(&type_args, &const_args, true).is_empty(),
            "move inference should reject const-only destinations"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_for_type_move_fallback_requires_writable_dst() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];
        let type_args: Vec<&UnknownStackObjectArgInfo> = args.iter().collect();
        let const_args: std::collections::BTreeSet<usize> = [1usize].into_iter().collect();

        assert!(
            infer_unknown_stack_object_copy_args_for_type(&type_args, &const_args, true).is_empty(),
            "unnamed move fallback should reject const destinations"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_from_const_hints() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];
        let type_args: Vec<&UnknownStackObjectArgInfo> = args.iter().collect();
        let const_args: std::collections::BTreeSet<usize> = [0usize].into_iter().collect();

        let inferred =
            infer_unknown_stack_object_copy_args_from_const_hints(&type_args, &const_args, false);
        assert_eq!(
            inferred.len(),
            2,
            "expected const source -> two destinations"
        );
        assert!(
            inferred
                .iter()
                .any(|(src, dst)| src.arg_idx == 0 && dst.arg_idx == 1)
        );
        assert!(
            inferred
                .iter()
                .any(|(src, dst)| src.arg_idx == 0 && dst.arg_idx == 2)
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_from_const_hints_move_requires_single_dst() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];
        let type_args: Vec<&UnknownStackObjectArgInfo> = args.iter().collect();
        let const_args: std::collections::BTreeSet<usize> = [0usize].into_iter().collect();

        assert!(
            infer_unknown_stack_object_copy_args_from_const_hints(&type_args, &const_args, true)
                .is_empty(),
            "move semantics should require a single non-const destination"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_from_const_hints_requires_unique_source() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];
        let type_args: Vec<&UnknownStackObjectArgInfo> = args.iter().collect();
        let const_args: std::collections::BTreeSet<usize> = [0usize, 1usize].into_iter().collect();

        assert!(
            infer_unknown_stack_object_copy_args_from_const_hints(&type_args, &const_args, false)
                .is_empty(),
            "const-hint fallback should reject ambiguous const sources"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_requires_matching_types() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_other".to_string(),
                named_out: true,
                named_in: false,
            },
        ];

        assert!(
            infer_unknown_stack_object_copy_args(&args, false).is_empty(),
            "copy semantics require matching stack-object types for src and dst"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_supports_multiple_type_pairs() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_custom".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 3,
                type_name: "bpf_custom".to_string(),
                named_out: true,
                named_in: false,
            },
        ];

        let copies = infer_unknown_stack_object_copy_args(&args, false);
        assert_eq!(copies.len(), 2, "expected two inferred copy pairs");
        assert!(
            copies.iter().any(|(src, dst)| src.arg_idx == 0
                && dst.arg_idx == 1
                && src.type_name == "bpf_wq")
        );
        assert!(copies.iter().any(|(src, dst)| {
            src.arg_idx == 2 && dst.arg_idx == 3 && src.type_name == "bpf_custom"
        }));
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_keeps_unambiguous_type_pairs() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 3,
                type_name: "bpf_custom".to_string(),
                named_out: false,
                named_in: true,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 4,
                type_name: "bpf_custom".to_string(),
                named_out: true,
                named_in: false,
            },
        ];

        let copies = infer_unknown_stack_object_copy_args(&args, false);
        assert_eq!(
            copies.len(),
            3,
            "expected two wq destinations plus custom pair"
        );
        assert!(
            copies.iter().any(|(src, dst)| src.arg_idx == 0
                && dst.arg_idx == 1
                && src.type_name == "bpf_wq")
        );
        assert!(
            copies.iter().any(|(src, dst)| src.arg_idx == 0
                && dst.arg_idx == 2
                && src.type_name == "bpf_wq")
        );
        assert!(copies.iter().any(|(src, dst)| {
            src.arg_idx == 3 && dst.arg_idx == 4 && src.type_name == "bpf_custom"
        }));
    }

    #[test]
    fn test_infer_unknown_stack_object_copy_args_rejects_ambiguous_source() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 2,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
        ];

        assert!(
            infer_unknown_stack_object_copy_args(&args, false).is_empty(),
            "copy inference should reject ambiguous source candidates"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_lifecycle_arg_prefers_named_input_for_destroy() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
        ];
        let const_args = std::collections::BTreeSet::new();

        let selected = infer_unknown_stack_object_lifecycle_arg(
            &args,
            KfuncUnknownStackObjectLifecycleOp::Destroy,
            &const_args,
        )
        .expect("expected named-in arg to disambiguate destroy lifecycle");
        assert_eq!(selected.arg_idx, 1);
    }

    #[test]
    fn test_infer_unknown_stack_object_lifecycle_arg_requires_unique_match() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];
        let const_args = std::collections::BTreeSet::new();

        assert!(
            infer_unknown_stack_object_lifecycle_arg(
                &args,
                KfuncUnknownStackObjectLifecycleOp::Destroy,
                &const_args,
            )
            .is_none(),
            "ambiguous destroy candidates should not infer lifecycle semantics"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_lifecycle_arg_init_uses_named_out() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: true,
            },
        ];
        let const_args = std::collections::BTreeSet::new();

        let selected = infer_unknown_stack_object_lifecycle_arg(
            &args,
            KfuncUnknownStackObjectLifecycleOp::Init,
            &const_args,
        )
        .expect("expected named-out arg to identify init target");
        assert_eq!(selected.arg_idx, 0);
    }

    #[test]
    fn test_infer_unknown_stack_object_lifecycle_arg_init_prefers_writable_named_out() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: true,
                named_in: false,
            },
        ];
        let const_args: std::collections::BTreeSet<usize> = [0usize].into_iter().collect();

        let selected = infer_unknown_stack_object_lifecycle_arg(
            &args,
            KfuncUnknownStackObjectLifecycleOp::Init,
            &const_args,
        )
        .expect("expected writable named-out arg to be preferred for init");
        assert_eq!(selected.arg_idx, 1);
    }

    #[test]
    fn test_infer_unknown_stack_object_lifecycle_arg_init_rejects_const_only_target() {
        let args = vec![UnknownStackObjectArgInfo {
            arg_idx: 0,
            type_name: "bpf_wq".to_string(),
            named_out: true,
            named_in: false,
        }];
        let const_args: std::collections::BTreeSet<usize> = [0usize].into_iter().collect();

        assert!(
            infer_unknown_stack_object_lifecycle_arg(
                &args,
                KfuncUnknownStackObjectLifecycleOp::Init,
                &const_args
            )
            .is_none(),
            "init inference should reject const-only destination args"
        );
    }

    #[test]
    fn test_infer_unknown_stack_object_lifecycle_arg_from_const_hints_destroy() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];
        let const_args: std::collections::BTreeSet<usize> = [1usize].into_iter().collect();

        let selected = infer_unknown_stack_object_lifecycle_arg_from_const_hints(
            &args,
            KfuncUnknownStackObjectLifecycleOp::Destroy,
            &const_args,
        )
        .expect("expected const pointer hint to disambiguate destroy arg");
        assert_eq!(selected.arg_idx, 1);
    }

    #[test]
    fn test_infer_unknown_stack_object_lifecycle_arg_from_const_hints_init() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];
        let const_args: std::collections::BTreeSet<usize> = [0usize].into_iter().collect();

        let selected = infer_unknown_stack_object_lifecycle_arg_from_const_hints(
            &args,
            KfuncUnknownStackObjectLifecycleOp::Init,
            &const_args,
        )
        .expect("expected non-const pointer hint to disambiguate init arg");
        assert_eq!(selected.arg_idx, 1);
    }

    #[test]
    fn test_infer_unknown_stack_object_lifecycle_arg_from_const_hints_requires_unique() {
        let args = vec![
            UnknownStackObjectArgInfo {
                arg_idx: 0,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
            UnknownStackObjectArgInfo {
                arg_idx: 1,
                type_name: "bpf_wq".to_string(),
                named_out: false,
                named_in: false,
            },
        ];
        let const_args: std::collections::BTreeSet<usize> = [0usize, 1usize].into_iter().collect();

        assert!(
            infer_unknown_stack_object_lifecycle_arg_from_const_hints(
                &args,
                KfuncUnknownStackObjectLifecycleOp::Destroy,
                &const_args
            )
            .is_none(),
            "const-hint lifecycle fallback should reject ambiguous candidates"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_prefers_named_input() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 2,
                role: KfuncUnknownDynptrArgRole::Out,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[1], &[], false),
            vec![(1, 2)],
            "named input should disambiguate dynptr copy source"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_requires_unique_source() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 2,
                role: KfuncUnknownDynptrArgRole::Out,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[], &[], false),
            Vec::<(usize, usize)>::new(),
            "multiple possible source dynptr args should not infer copy semantics"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_falls_back_without_out_hints() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::In,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[], &[], false),
            vec![(0, 1)],
            "unnamed two-arg fallback should infer arg0->arg1"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_fallback_prefers_named_input() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::In,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[1], &[], false),
            vec![(1, 0)],
            "unnamed fallback should prefer the uniquely named-in source"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_fallback_requires_two_args() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 2,
                role: KfuncUnknownDynptrArgRole::In,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[], &[], false),
            Vec::<(usize, usize)>::new(),
            "unnamed fallback should require exactly two args"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_prefers_const_input_hint() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 2,
                role: KfuncUnknownDynptrArgRole::Out,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[], &[1], false),
            vec![(1, 2)],
            "const-qualified unique input should disambiguate dynptr source"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_prefers_non_const_destination() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::Out,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 2,
                role: KfuncUnknownDynptrArgRole::Out,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[0], &[1], false),
            vec![(0, 2)],
            "copy inference should prefer non-const destinations when available"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_falls_back_to_const_destination() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::Out,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[0], &[1], false),
            vec![(0, 1)],
            "copy inference should still use const destination when no alternative exists"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_move_requires_writable_destination() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::Out,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[0], &[1], true),
            Vec::<(usize, usize)>::new(),
            "move inference should reject const-only destinations"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_move_fallback_requires_writable_destination() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::In,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[0], &[1], true),
            Vec::<(usize, usize)>::new(),
            "unnamed move fallback should reject const destinations"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_allows_multiple_destinations_for_copy() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::Out,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 2,
                role: KfuncUnknownDynptrArgRole::Out,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[0], &[], false),
            vec![(0, 1), (0, 2)],
            "copy-like dynptr transfers should infer all unambiguous destination pairs"
        );
    }

    #[test]
    fn test_infer_unknown_dynptr_copy_args_move_requires_single_destination() {
        let args = vec![
            KfuncUnknownDynptrArg {
                arg_idx: 0,
                role: KfuncUnknownDynptrArgRole::In,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 1,
                role: KfuncUnknownDynptrArgRole::Out,
            },
            KfuncUnknownDynptrArg {
                arg_idx: 2,
                role: KfuncUnknownDynptrArgRole::Out,
            },
        ];

        assert_eq!(
            infer_unknown_dynptr_copy_args(&args, &[0], &[], true),
            Vec::<(usize, usize)>::new(),
            "move-like dynptr transfers should require a single destination"
        );
    }
}
