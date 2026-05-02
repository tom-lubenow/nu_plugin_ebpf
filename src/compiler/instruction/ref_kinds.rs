use super::*;
use crate::kernel_btf::{KernelBtf, KfuncPointerRefFamily};
use std::collections::{BTreeMap, BTreeSet};

#[path = "ref_kinds/semantics.rs"]
mod semantics;
#[path = "ref_kinds/unknown.rs"]
mod unknown;

pub use semantics::kfunc_semantics;
pub use unknown::{
    kfunc_unknown_dynptr_args, kfunc_unknown_dynptr_copy, kfunc_unknown_iter_lifecycle,
    kfunc_unknown_stack_object_copy, kfunc_unknown_stack_object_lifecycle,
};

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

pub fn kfunc_ref_kind_from_bpf_type_name(type_name: &str) -> Option<KfuncRefKind> {
    let type_name = type_name.strip_prefix("struct ").unwrap_or(type_name);
    match type_name {
        "task_struct" => Some(KfuncRefKind::Task),
        "cgroup" => Some(KfuncRefKind::Cgroup),
        "inode" => Some(KfuncRefKind::Inode),
        "bpf_cpumask" | "cpumask" => Some(KfuncRefKind::Cpumask),
        "bpf_crypto_ctx" => Some(KfuncRefKind::CryptoCtx),
        "file" => Some(KfuncRefKind::File),
        "sock" | "socket" | "tcp_sock" | "inet_sock" | "udp_sock" | "unix_sock"
        | "request_sock" | "inet_timewait_sock" => Some(KfuncRefKind::Socket),
        _ => None,
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

pub fn kfunc_iter_lifecycle(kfunc: &str) -> Option<KfuncUnknownIterLifecycle> {
    let known = match kfunc {
        "bpf_iter_task_vma_new" => Some((KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::New)),
        "bpf_iter_task_vma_next" => Some((KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::Next)),
        "bpf_iter_task_vma_destroy" => {
            Some((KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::Destroy))
        }
        "bpf_iter_task_new" => Some((KfuncIterFamily::Task, KfuncIterLifecycleOp::New)),
        "bpf_iter_task_next" => Some((KfuncIterFamily::Task, KfuncIterLifecycleOp::Next)),
        "bpf_iter_task_destroy" => Some((KfuncIterFamily::Task, KfuncIterLifecycleOp::Destroy)),
        "bpf_iter_scx_dsq_new" => Some((KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::New)),
        "bpf_iter_scx_dsq_next" => Some((KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::Next)),
        "bpf_iter_scx_dsq_destroy" => {
            Some((KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::Destroy))
        }
        "scx_bpf_dsq_move"
        | "scx_bpf_dsq_move_vtime"
        | "scx_bpf_dsq_move_set_slice"
        | "scx_bpf_dsq_move_set_vtime" => {
            Some((KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::Next))
        }
        "bpf_iter_num_new" => Some((KfuncIterFamily::Num, KfuncIterLifecycleOp::New)),
        "bpf_iter_num_next" => Some((KfuncIterFamily::Num, KfuncIterLifecycleOp::Next)),
        "bpf_iter_num_destroy" => Some((KfuncIterFamily::Num, KfuncIterLifecycleOp::Destroy)),
        "bpf_iter_bits_new" => Some((KfuncIterFamily::Bits, KfuncIterLifecycleOp::New)),
        "bpf_iter_bits_next" => Some((KfuncIterFamily::Bits, KfuncIterLifecycleOp::Next)),
        "bpf_iter_bits_destroy" => Some((KfuncIterFamily::Bits, KfuncIterLifecycleOp::Destroy)),
        "bpf_iter_css_new" => Some((KfuncIterFamily::Css, KfuncIterLifecycleOp::New)),
        "bpf_iter_css_next" => Some((KfuncIterFamily::Css, KfuncIterLifecycleOp::Next)),
        "bpf_iter_css_destroy" => Some((KfuncIterFamily::Css, KfuncIterLifecycleOp::Destroy)),
        "bpf_iter_css_task_new" => Some((KfuncIterFamily::CssTask, KfuncIterLifecycleOp::New)),
        "bpf_iter_css_task_next" => Some((KfuncIterFamily::CssTask, KfuncIterLifecycleOp::Next)),
        "bpf_iter_css_task_destroy" => {
            Some((KfuncIterFamily::CssTask, KfuncIterLifecycleOp::Destroy))
        }
        "bpf_iter_dmabuf_new" => Some((KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::New)),
        "bpf_iter_dmabuf_next" => Some((KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::Next)),
        "bpf_iter_dmabuf_destroy" => Some((KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::Destroy)),
        "bpf_iter_kmem_cache_new" => Some((KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::New)),
        "bpf_iter_kmem_cache_next" => {
            Some((KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::Next))
        }
        "bpf_iter_kmem_cache_destroy" => {
            Some((KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::Destroy))
        }
        _ => None,
    };
    if let Some((family, op)) = known {
        return Some(KfuncUnknownIterLifecycle {
            family,
            op,
            arg_idx: 0,
        });
    }

    kfunc_unknown_iter_lifecycle(kfunc)
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
    pub type_id: Option<u32>,
    pub op: KfuncUnknownStackObjectLifecycleOp,
    pub arg_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KfuncUnknownStackObjectCopy {
    pub type_name: String,
    pub type_id: Option<u32>,
    pub src_arg_idx: usize,
    pub dst_arg_idx: usize,
    pub move_semantics: bool,
}

fn should_infer_unknown_acquire_ref(
    kfunc: &str,
    kind: KfuncRefKind,
    has_same_family_arg: bool,
    has_const_only_same_family_args: bool,
    has_unique_writable_named_in_same_family_arg: bool,
    has_writable_named_out_same_family_arg: bool,
) -> bool {
    if is_release_like_kfunc_name(kfunc) {
        return false;
    }
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
        || (has_unique_writable_named_in_same_family_arg && !has_writable_named_out_same_family_arg)
}

fn is_release_like_kfunc_name(kfunc: &str) -> bool {
    let lower = kfunc.to_ascii_lowercase();
    lower.contains("_release")
        || lower.contains("_destroy")
        || lower.contains("_cleanup")
        || lower.contains("_deinit")
        || lower.contains("_fini_")
        || lower.ends_with("_fini")
        || lower.contains("_delete")
        || lower.contains("_detach")
        || lower.contains("_close")
        || lower.contains("_unref")
        || lower.starts_with("bpf_put_")
        || lower.contains("_put_")
        || lower.ends_with("_put")
        || lower.contains("_drop")
        || lower.contains("_free")
        || lower.contains("_dec_")
        || lower.ends_with("_dec")
}

pub fn kfunc_acquire_ref_kind(kfunc: &str) -> Option<KfuncRefKind> {
    match kfunc {
        "bpf_task_acquire" | "bpf_task_from_pid" | "bpf_task_from_vpid" => Some(KfuncRefKind::Task),
        "bpf_task_get_cgroup1"
        | "bpf_cgroup_acquire"
        | "bpf_cgroup_ancestor"
        | "bpf_cgroup_from_id" => Some(KfuncRefKind::Cgroup),
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
                let mut same_family_writable_named_in_count = 0usize;
                let mut has_writable_named_out_same_family_arg = false;
                for arg_idx in 0..5 {
                    if kernel_btf
                        .kfunc_pointer_arg_ref_family(kfunc, arg_idx)
                        .map(ref_kind_from_btf_family)
                        != Some(kind)
                    {
                        continue;
                    }
                    has_same_family_arg = true;
                    let is_const = kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx);
                    if !is_const {
                        has_non_const_same_family_arg = true;
                    }
                    if !is_const && kernel_btf.kfunc_pointer_arg_is_named_in(kfunc, arg_idx) {
                        same_family_writable_named_in_count += 1;
                    }
                    if !is_const && kernel_btf.kfunc_pointer_arg_is_named_out(kfunc, arg_idx) {
                        has_writable_named_out_same_family_arg = true;
                    }
                }
                let has_const_only_same_family_args =
                    has_same_family_arg && !has_non_const_same_family_arg;
                let has_unique_writable_named_in_same_family_arg =
                    same_family_writable_named_in_count == 1;
                if should_infer_unknown_acquire_ref(
                    kfunc,
                    kind,
                    has_same_family_arg,
                    has_const_only_same_family_args,
                    has_unique_writable_named_in_same_family_arg,
                    has_writable_named_out_same_family_arg,
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
            if KfuncSignature::for_name(kfunc).is_none() && is_release_like_kfunc_name(kfunc) {
                let kernel_btf = KernelBtf::get();
                let mut candidates: Vec<(usize, Option<KfuncRefKind>, bool, bool)> = Vec::new();
                let mut candidates_with_out: Vec<(usize, Option<KfuncRefKind>, bool, bool, bool)> =
                    Vec::new();
                for arg_idx in 0..5 {
                    let candidate = (
                        arg_idx,
                        kernel_btf
                            .kfunc_pointer_arg_ref_family(kfunc, arg_idx)
                            .map(ref_kind_from_btf_family),
                        kernel_btf.kfunc_pointer_arg_is_named_in(kfunc, arg_idx),
                        kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx),
                    );
                    candidates.push(candidate);
                    candidates_with_out.push((
                        candidate.0,
                        candidate.1,
                        candidate.2,
                        candidate.3,
                        kernel_btf.kfunc_pointer_arg_is_named_out(kfunc, arg_idx),
                    ));
                }
                if let Some(kind) = infer_release_kind_from_arg_index(
                    kernel_btf.kfunc_release_ref_arg_index(kfunc),
                    &candidates,
                ) {
                    return Some(kind);
                }
                if let Some(kind) = infer_release_kind_from_name_hints(kfunc, &candidates)
                    && let Some(filtered) =
                        filter_release_kind_preferring_non_out(kind, &candidates_with_out)
                {
                    return Some(filtered);
                }
                if let Some(kind) = infer_release_kind_from_named_inputs(&candidates)
                    && let Some(filtered) =
                        filter_release_kind_preferring_non_out(kind, &candidates_with_out)
                {
                    return Some(filtered);
                }
                if let Some(kind) =
                    infer_unique_release_kind_preferring_non_out(&candidates_with_out)
                {
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

fn infer_release_kind_from_name_hints(
    kfunc: &str,
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool)],
) -> Option<KfuncRefKind> {
    let mut candidate_kinds = Vec::new();
    for (_, kind, _, _) in candidates {
        if let Some(kind) = kind
            && !candidate_kinds.contains(kind)
        {
            candidate_kinds.push(*kind);
        }
    }
    if candidate_kinds.is_empty() {
        return None;
    }

    let lower = kfunc.to_ascii_lowercase();
    let mut hinted_kinds = Vec::new();
    let mut push_if_matches = |kind: KfuncRefKind, condition: bool| {
        if condition && candidate_kinds.contains(&kind) && !hinted_kinds.contains(&kind) {
            hinted_kinds.push(kind);
        }
    };
    push_if_matches(KfuncRefKind::Task, lower.contains("task"));
    push_if_matches(KfuncRefKind::Cgroup, lower.contains("cgroup"));
    push_if_matches(KfuncRefKind::Cpumask, lower.contains("cpumask"));
    push_if_matches(KfuncRefKind::Inode, lower.contains("inode"));
    push_if_matches(KfuncRefKind::File, lower.contains("file"));
    push_if_matches(
        KfuncRefKind::Socket,
        lower.contains("socket") || lower.contains("sock"),
    );
    push_if_matches(
        KfuncRefKind::CryptoCtx,
        lower.contains("crypto_ctx") || lower.contains("crypto"),
    );

    if hinted_kinds.len() == 1 {
        return hinted_kinds.first().copied();
    }
    None
}

fn infer_release_kind_from_named_inputs(
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool)],
) -> Option<KfuncRefKind> {
    let select_unique = |prefer_non_const: bool| {
        let mut selected: Option<KfuncRefKind> = None;
        for (_, kind, named_in, is_const) in candidates {
            if !*named_in || (prefer_non_const && *is_const) {
                continue;
            }
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
    };
    if let Some(kind) = select_unique(true) {
        return Some(kind);
    }
    select_unique(false)
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

fn infer_unique_release_kind_preferring_non_out(
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool, bool)],
) -> Option<KfuncRefKind> {
    let mut non_out = Vec::new();
    let mut all = Vec::new();
    for (arg_idx, kind, named_in, is_const, named_out) in candidates {
        let candidate = (*arg_idx, *kind, *named_in, *is_const);
        all.push(candidate);
        if !*named_out {
            non_out.push(candidate);
        }
    }
    infer_unique_release_kind(&non_out).or_else(|| infer_unique_release_kind(&all))
}

fn infer_unique_release_arg_from_kind_preferring_non_out(
    expected_kind: KfuncRefKind,
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool, bool)],
) -> Option<usize> {
    let mut non_out = Vec::new();
    let mut all = Vec::new();
    for (arg_idx, kind, named_in, is_const, named_out) in candidates {
        let candidate = (*arg_idx, *kind, *named_in, *is_const);
        all.push(candidate);
        if !*named_out {
            non_out.push(candidate);
        }
    }
    infer_unique_release_arg_from_kind(expected_kind, &non_out)
        .or_else(|| infer_unique_release_arg_from_kind(expected_kind, &all))
}

fn filter_release_kind_preferring_non_out(
    kind: KfuncRefKind,
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool, bool)],
) -> Option<KfuncRefKind> {
    let has_any_non_out_ref = candidates
        .iter()
        .any(|(_, candidate_kind, _, _, named_out)| !*named_out && candidate_kind.is_some());
    if !has_any_non_out_ref {
        return Some(kind);
    }
    let has_non_out_for_kind = candidates
        .iter()
        .any(|(_, candidate_kind, _, _, named_out)| !*named_out && *candidate_kind == Some(kind));
    if has_non_out_for_kind {
        Some(kind)
    } else {
        None
    }
}

fn infer_release_kind_from_arg_index(
    release_arg_idx: Option<usize>,
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool)],
) -> Option<KfuncRefKind> {
    let release_arg_idx = release_arg_idx?;
    candidates
        .iter()
        .find(|(arg_idx, _, _, _)| *arg_idx == release_arg_idx)
        .and_then(|(_, kind, _, _)| *kind)
}

fn release_arg_index_matches_expected_kind(
    arg_idx: usize,
    expected_kind: KfuncRefKind,
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool)],
) -> bool {
    match candidates
        .iter()
        .find(|(candidate_idx, _, _, _)| *candidate_idx == arg_idx)
    {
        Some((_, kind, _, _)) => kind.is_none() || *kind == Some(expected_kind),
        None => true,
    }
}

fn fallback_release_arg_index_from_arg0(
    expected_kind: KfuncRefKind,
    arg0_kind: Option<KfuncRefKind>,
) -> Option<usize> {
    match arg0_kind {
        Some(kind) if kind != expected_kind => None,
        _ => Some(0),
    }
}

fn fallback_release_arg_index_from_arg0_preferring_non_out(
    expected_kind: KfuncRefKind,
    arg0_kind: Option<KfuncRefKind>,
    arg0_named_out: bool,
    candidates: &[(usize, Option<KfuncRefKind>, bool, bool, bool)],
) -> Option<usize> {
    if arg0_named_out {
        let has_non_out_expected_kind = candidates
            .iter()
            .any(|(_, kind, _, _, named_out)| !*named_out && *kind == Some(expected_kind));
        if has_non_out_expected_kind {
            return None;
        }
    }
    fallback_release_arg_index_from_arg0(expected_kind, arg0_kind)
}

pub fn kfunc_release_ref_arg_index(kfunc: &str) -> Option<usize> {
    match kfunc {
        "bpf_list_push_front_impl" | "bpf_list_push_back_impl" | "bpf_rbtree_add_impl" => Some(1),
        _ if kfunc_release_ref_kind(kfunc).is_some() => {
            if KfuncSignature::for_name(kfunc).is_none() {
                let kernel_btf = KernelBtf::get();
                if let Some(expected_kind) = kfunc_release_ref_kind(kfunc) {
                    let mut candidates: Vec<(usize, Option<KfuncRefKind>, bool, bool)> = Vec::new();
                    let mut candidates_with_out: Vec<(
                        usize,
                        Option<KfuncRefKind>,
                        bool,
                        bool,
                        bool,
                    )> = Vec::new();
                    for arg_idx in 0..5 {
                        let candidate = (
                            arg_idx,
                            kernel_btf
                                .kfunc_pointer_arg_ref_family(kfunc, arg_idx)
                                .map(ref_kind_from_btf_family),
                            kernel_btf.kfunc_pointer_arg_is_named_in(kfunc, arg_idx),
                            kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg_idx),
                        );
                        candidates.push(candidate);
                        candidates_with_out.push((
                            candidate.0,
                            candidate.1,
                            candidate.2,
                            candidate.3,
                            kernel_btf.kfunc_pointer_arg_is_named_out(kfunc, arg_idx),
                        ));
                    }
                    if let Some(arg_idx) = kernel_btf.kfunc_release_ref_arg_index(kfunc)
                        && release_arg_index_matches_expected_kind(
                            arg_idx,
                            expected_kind,
                            &candidates,
                        )
                    {
                        return Some(arg_idx);
                    }
                    if let Some(arg_idx) =
                        infer_release_arg_from_named_inputs(expected_kind, &candidates)
                    {
                        return Some(arg_idx);
                    }
                    if let Some(arg_idx) = infer_unique_release_arg_from_kind_preferring_non_out(
                        expected_kind,
                        &candidates_with_out,
                    ) {
                        return Some(arg_idx);
                    }

                    let arg0_kind = kernel_btf
                        .kfunc_pointer_arg_ref_family(kfunc, 0)
                        .map(ref_kind_from_btf_family);
                    let arg0_named_out = kernel_btf.kfunc_pointer_arg_is_named_out(kfunc, 0);
                    return fallback_release_arg_index_from_arg0_preferring_non_out(
                        expected_kind,
                        arg0_kind,
                        arg0_named_out,
                        &candidates_with_out,
                    );
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
            | BpfHelper::TcpSendAck
            | BpfHelper::GetListenerSock
            | BpfHelper::TcpCheckSyncookie
            | BpfHelper::TcpGenSyncookie
            | BpfHelper::SkcToTcp6Sock
            | BpfHelper::SkcToTcpSock
            | BpfHelper::SkcToTcpTimewaitSock
            | BpfHelper::SkcToTcpRequestSock
            | BpfHelper::SkcToUdp6Sock
            | BpfHelper::SkcToMptcpSock
            | BpfHelper::SkcToUnixSock,
            0,
        )
        | (BpfHelper::SkStorageGet | BpfHelper::SkStorageDelete | BpfHelper::SkAssign, 1) => {
            Some(KfuncRefKind::Socket)
        }
        (BpfHelper::TaskStorageGet | BpfHelper::TaskStorageDelete, 1)
        | (BpfHelper::TaskPtRegs | BpfHelper::GetTaskStack, 0)
        | (BpfHelper::FindVma, 0)
        | (BpfHelper::CopyFromUserTask, 3) => Some(KfuncRefKind::Task),
        (BpfHelper::InodeStorageGet | BpfHelper::InodeStorageDelete, 1)
        | (BpfHelper::ImaInodeHash, 0) => Some(KfuncRefKind::Inode),
        (BpfHelper::CgrpStorageGet | BpfHelper::CgrpStorageDelete, 1) => Some(KfuncRefKind::Cgroup),
        (BpfHelper::SockFromFile | BpfHelper::ImaFileHash, 0) => Some(KfuncRefKind::File),
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
            | ("bpf_sock_ops_enable_tx_tstamp", 0)
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
            | ("scx_bpf_select_cpu_dfl", 3)
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
            | ("scx_bpf_select_cpu_dfl", 3)
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
#[path = "ref_kinds/tests.rs"]
mod tests;
