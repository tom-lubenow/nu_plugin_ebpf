use super::*;

pub(super) fn iter_lifecycle_op_from_kfunc_name(kfunc: &str) -> Option<KfuncIterLifecycleOp> {
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

pub(super) fn iter_family_from_stack_object_type_name(type_name: &str) -> Option<KfuncIterFamily> {
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

pub(super) fn is_dynptr_stack_object_type_name(type_name: &str) -> bool {
    type_name == "bpf_dynptr" || type_name.starts_with("bpf_dynptr_")
}

pub(super) fn is_special_stack_object_type_name(type_name: &str) -> bool {
    iter_family_from_stack_object_type_name(type_name).is_some()
        || is_dynptr_stack_object_type_name(type_name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UnknownStackObjectArgInfo {
    pub(super) arg_idx: usize,
    pub(super) type_name: String,
    pub(super) named_out: bool,
    pub(super) named_in: bool,
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
    if let Some(args) = known_dynptr_args(kfunc) {
        return args.to_vec();
    }
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

fn known_dynptr_args(kfunc: &str) -> Option<&'static [KfuncUnknownDynptrArg]> {
    use KfuncUnknownDynptrArgRole::{In, Out};

    const ARG0_IN: &[KfuncUnknownDynptrArg] = &[KfuncUnknownDynptrArg {
        arg_idx: 0,
        role: In,
    }];
    const ARG0_OUT: &[KfuncUnknownDynptrArg] = &[KfuncUnknownDynptrArg {
        arg_idx: 0,
        role: Out,
    }];
    const DYNPTR_CLONE: &[KfuncUnknownDynptrArg] = &[
        KfuncUnknownDynptrArg {
            arg_idx: 0,
            role: In,
        },
        KfuncUnknownDynptrArg {
            arg_idx: 1,
            role: Out,
        },
    ];
    const DYNPTR_COPY: &[KfuncUnknownDynptrArg] = &[
        KfuncUnknownDynptrArg {
            arg_idx: 0,
            role: In,
        },
        KfuncUnknownDynptrArg {
            arg_idx: 2,
            role: In,
        },
    ];

    Some(match kfunc {
        "bpf_copy_from_user_dynptr"
        | "bpf_copy_from_user_task_dynptr"
        | "bpf_copy_from_user_task_str_dynptr" => ARG0_OUT,
        "bpf_dynptr_adjust"
        | "bpf_dynptr_size"
        | "bpf_dynptr_is_null"
        | "bpf_dynptr_is_rdonly"
        | "bpf_dynptr_memset"
        | "bpf_dynptr_slice"
        | "bpf_dynptr_slice_rdwr" => ARG0_IN,
        "bpf_dynptr_clone" => DYNPTR_CLONE,
        "bpf_dynptr_copy" => DYNPTR_COPY,
        _ => return None,
    })
}

pub(super) fn infer_unknown_dynptr_copy_args(
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

pub(super) fn unknown_transfer_move_semantics_from_kfunc_name(kfunc: &str) -> Option<bool> {
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

pub(super) fn unknown_copy_move_semantics_with_named_pair_fallback(kfunc: &str) -> Option<bool> {
    let transfer_move_semantics = unknown_transfer_move_semantics_from_kfunc_name(kfunc);
    if transfer_move_semantics.is_some() {
        return transfer_move_semantics;
    }
    if unknown_stack_object_lifecycle_op_from_kfunc_name(kfunc).is_some() {
        return None;
    }
    Some(false)
}

pub fn kfunc_unknown_dynptr_copy(kfunc: &str) -> Vec<KfuncUnknownDynptrCopy> {
    if kfunc == "bpf_dynptr_clone" {
        return vec![KfuncUnknownDynptrCopy {
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: false,
        }];
    }
    if KfuncSignature::for_name(kfunc).is_some() {
        return Vec::new();
    }
    let Some(move_semantics) = unknown_copy_move_semantics_with_named_pair_fallback(kfunc) else {
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

pub(super) fn unknown_stack_object_lifecycle_op_from_kfunc_name(
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

pub(super) fn unknown_stack_object_args(kfunc: &str) -> Vec<UnknownStackObjectArgInfo> {
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

pub(super) fn infer_unknown_stack_object_copy_from_candidates<'a>(
    candidates: Vec<(&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo)>,
    const_arg_indices: &BTreeSet<usize>,
    move_semantics: bool,
) -> Vec<(&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo)> {
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
}

pub(super) fn infer_unknown_stack_object_copy_args_for_type<'a>(
    args: &[&'a UnknownStackObjectArgInfo],
    const_arg_indices: &BTreeSet<usize>,
    move_semantics: bool,
) -> Vec<(&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo)> {
    if args.len() < 2 {
        return Vec::new();
    }

    let mut candidates: Vec<(&UnknownStackObjectArgInfo, &UnknownStackObjectArgInfo)> = Vec::new();
    for src in args.iter().copied().filter(|arg| arg.named_in) {
        for dst in args.iter().copied().filter(|arg| arg.named_out) {
            if src.arg_idx == dst.arg_idx || src.type_name != dst.type_name {
                continue;
            }
            candidates.push((src, dst));
        }
    }
    let inferred = infer_unknown_stack_object_copy_from_candidates(
        candidates,
        const_arg_indices,
        move_semantics,
    );
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

    let inferred = infer_unknown_stack_object_copy_from_candidates(
        candidates,
        const_arg_indices,
        move_semantics,
    );
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

pub(super) fn infer_unknown_stack_object_copy_args_from_named_pairs_for_type<'a>(
    args: &[&'a UnknownStackObjectArgInfo],
    const_arg_indices: &BTreeSet<usize>,
) -> Vec<(&'a UnknownStackObjectArgInfo, &'a UnknownStackObjectArgInfo)> {
    if args.len() < 2 {
        return Vec::new();
    }

    let mut candidates: Vec<(&UnknownStackObjectArgInfo, &UnknownStackObjectArgInfo)> = Vec::new();
    for src in args.iter().copied().filter(|arg| arg.named_in) {
        for dst in args.iter().copied().filter(|arg| arg.named_out) {
            if src.arg_idx == dst.arg_idx || src.type_name != dst.type_name {
                continue;
            }
            candidates.push((src, dst));
        }
    }
    infer_unknown_stack_object_copy_from_candidates(candidates, const_arg_indices, false)
}

pub(super) fn infer_unknown_stack_object_copy_args_from_const_hints<'a>(
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

pub(super) fn infer_unknown_stack_object_lifecycle_arg<'a>(
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

pub(super) fn infer_unknown_stack_object_lifecycle_arg_from_const_hints<'a>(
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

pub(super) fn infer_unknown_stack_object_init_arg_from_named_out_fallback(
    args: &[UnknownStackObjectArgInfo],
) -> Option<&UnknownStackObjectArgInfo> {
    if args.is_empty() {
        return None;
    }

    // Conservative shape fallback: treat a single writable named-out stack
    // object arg (with no named-in stack object args) as an init target.
    if args.iter().any(|arg| arg.named_in) {
        return None;
    }
    let named_out_args: Vec<&UnknownStackObjectArgInfo> =
        args.iter().filter(|arg| arg.named_out).collect();
    if named_out_args.len() != 1 {
        return None;
    }
    named_out_args.first().copied()
}

pub fn kfunc_unknown_stack_object_lifecycle(
    kfunc: &str,
) -> Option<KfuncUnknownStackObjectLifecycle> {
    let args = unknown_stack_object_args(kfunc);
    let kernel_btf = KernelBtf::get();
    let const_args: BTreeSet<usize> = args
        .iter()
        .filter(|arg| kernel_btf.kfunc_pointer_arg_is_const(kfunc, arg.arg_idx))
        .map(|arg| arg.arg_idx)
        .collect();
    if let Some(op) = unknown_stack_object_lifecycle_op_from_kfunc_name(kfunc) {
        let arg =
            infer_unknown_stack_object_lifecycle_arg(&args, op, &const_args).or_else(|| {
                infer_unknown_stack_object_lifecycle_arg_from_const_hints(&args, op, &const_args)
            })?;
        return Some(KfuncUnknownStackObjectLifecycle {
            type_name: arg.type_name.clone(),
            type_id: kernel_btf.kfunc_pointer_arg_stack_object_type_id(kfunc, arg.arg_idx),
            op,
            arg_idx: arg.arg_idx,
        });
    }

    if unknown_transfer_move_semantics_from_kfunc_name(kfunc).is_some() {
        return None;
    }

    let arg = infer_unknown_stack_object_init_arg_from_named_out_fallback(&args)?;
    Some(KfuncUnknownStackObjectLifecycle {
        type_name: arg.type_name.clone(),
        type_id: kernel_btf.kfunc_pointer_arg_stack_object_type_id(kfunc, arg.arg_idx),
        op: KfuncUnknownStackObjectLifecycleOp::Init,
        arg_idx: arg.arg_idx,
    })
}

pub fn kfunc_unknown_stack_object_copy(kfunc: &str) -> Vec<KfuncUnknownStackObjectCopy> {
    if KfuncSignature::for_name(kfunc).is_some() {
        return Vec::new();
    }
    let transfer_move_semantics = unknown_transfer_move_semantics_from_kfunc_name(kfunc);
    let Some(move_semantics) = unknown_copy_move_semantics_with_named_pair_fallback(kfunc) else {
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
        let mut inferred = if transfer_move_semantics.is_some() {
            infer_unknown_stack_object_copy_args_for_type(
                type_args,
                &const_pointer_args,
                move_semantics,
            )
        } else {
            infer_unknown_stack_object_copy_args_from_named_pairs_for_type(
                type_args,
                &const_pointer_args,
            )
        };
        if inferred.is_empty() && transfer_move_semantics.is_some() {
            inferred = infer_unknown_stack_object_copy_args_from_const_hints(
                type_args,
                &const_pointer_args,
                move_semantics,
            );
        }
        for (src, dst) in inferred {
            copies.push(KfuncUnknownStackObjectCopy {
                type_name: src.type_name.clone(),
                type_id: kernel_btf.kfunc_pointer_arg_stack_object_type_id(kfunc, src.arg_idx),
                src_arg_idx: src.arg_idx,
                dst_arg_idx: dst.arg_idx,
                move_semantics,
            });
        }
    }
    copies
}
