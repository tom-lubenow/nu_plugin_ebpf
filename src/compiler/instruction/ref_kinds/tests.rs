use super::unknown::*;
use super::*;

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
fn test_known_kfunc_iter_lifecycle_table() {
    assert_eq!(
        kfunc_iter_lifecycle("bpf_iter_task_vma_new"),
        Some(KfuncUnknownIterLifecycle {
            family: KfuncIterFamily::TaskVma,
            op: KfuncIterLifecycleOp::New,
            arg_idx: 0,
        })
    );
    assert_eq!(
        kfunc_iter_lifecycle("bpf_iter_css_task_destroy"),
        Some(KfuncUnknownIterLifecycle {
            family: KfuncIterFamily::CssTask,
            op: KfuncIterLifecycleOp::Destroy,
            arg_idx: 0,
        })
    );
    assert_eq!(
        kfunc_iter_lifecycle("scx_bpf_dsq_move_set_slice"),
        Some(KfuncUnknownIterLifecycle {
            family: KfuncIterFamily::ScxDsq,
            op: KfuncIterLifecycleOp::Next,
            arg_idx: 0,
        })
    );
    assert_eq!(kfunc_iter_lifecycle("bpf_task_from_pid"), None);
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
        false,
        false,
        false
    ));
    assert!(should_infer_unknown_acquire_ref(
        "bpf_get_foo_task",
        KfuncRefKind::Task,
        true,
        false,
        false,
        false
    ));
    assert!(should_infer_unknown_acquire_ref(
        "foo_get_task",
        KfuncRefKind::Task,
        true,
        false,
        false,
        false
    ));
    assert!(should_infer_unknown_acquire_ref(
        "foo_task_get",
        KfuncRefKind::Task,
        true,
        false,
        false,
        false
    ));
    assert!(should_infer_unknown_acquire_ref(
        "foo_task_dup",
        KfuncRefKind::Task,
        true,
        false,
        false,
        false
    ));
    assert!(should_infer_unknown_acquire_ref(
        "foo_task_clone",
        KfuncRefKind::Task,
        true,
        false,
        false,
        false
    ));
    assert!(should_infer_unknown_acquire_ref(
        "foo_lookup_sock",
        KfuncRefKind::Socket,
        true,
        false,
        false,
        false
    ));
}

#[test]
fn test_should_infer_unknown_acquire_ref_without_same_family_args() {
    assert!(should_infer_unknown_acquire_ref(
        "foo_plain_name",
        KfuncRefKind::Task,
        false,
        false,
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
        true,
        false,
        false
    ));
}

#[test]
fn test_should_not_infer_unknown_acquire_ref_without_hints_when_same_family_arg_exists() {
    assert!(!should_infer_unknown_acquire_ref(
        "foo_plain_name",
        KfuncRefKind::Task,
        true,
        false,
        false,
        false
    ));
}

#[test]
fn test_should_not_infer_unknown_acquire_ref_for_release_like_names() {
    assert!(!should_infer_unknown_acquire_ref(
        "foo_task_release_ref",
        KfuncRefKind::Task,
        false,
        false,
        false,
        false
    ));
    assert!(!should_infer_unknown_acquire_ref(
        "bpf_put_task_ref",
        KfuncRefKind::Task,
        false,
        false,
        false,
        false
    ));
}

#[test]
fn test_should_infer_unknown_acquire_ref_for_unique_named_in_without_named_out() {
    assert!(should_infer_unknown_acquire_ref(
        "foo_plain_name",
        KfuncRefKind::Task,
        true,
        false,
        true,
        false
    ));
}

#[test]
fn test_should_not_infer_unknown_acquire_ref_for_named_in_when_named_out_exists() {
    assert!(!should_infer_unknown_acquire_ref(
        "foo_plain_name",
        KfuncRefKind::Task,
        true,
        false,
        true,
        true
    ));
}

#[test]
fn test_is_release_like_kfunc_name() {
    assert!(is_release_like_kfunc_name("foo_task_release"));
    assert!(is_release_like_kfunc_name("foo_task_destroy"));
    assert!(is_release_like_kfunc_name("foo_task_cleanup"));
    assert!(is_release_like_kfunc_name("foo_task_deinit"));
    assert!(is_release_like_kfunc_name("foo_task_fini"));
    assert!(is_release_like_kfunc_name("bpf_put_task"));
    assert!(is_release_like_kfunc_name("foo_task_drop"));
    assert!(is_release_like_kfunc_name("foo_task_dec"));
    assert!(!is_release_like_kfunc_name("foo_task_acquire"));
    assert!(!is_release_like_kfunc_name("foo_task_get"));
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
fn test_unknown_copy_move_semantics_with_named_pair_fallback() {
    assert_eq!(
        unknown_copy_move_semantics_with_named_pair_fallback("foo_obj_copy"),
        Some(false)
    );
    assert_eq!(
        unknown_copy_move_semantics_with_named_pair_fallback("foo_obj_move"),
        Some(true)
    );
    assert_eq!(
        unknown_copy_move_semantics_with_named_pair_fallback("foo_obj_plain"),
        Some(false)
    );
    assert_eq!(
        unknown_copy_move_semantics_with_named_pair_fallback("foo_obj_init"),
        None
    );
    assert_eq!(
        unknown_copy_move_semantics_with_named_pair_fallback("foo_obj_destroy"),
        None
    );
}

#[test]
fn test_infer_release_kind_from_name_hints_selects_task() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false),
        (1usize, Some(KfuncRefKind::Cgroup), false, false),
    ];
    assert_eq!(
        infer_release_kind_from_name_hints("foo_task_release", &candidates),
        Some(KfuncRefKind::Task)
    );
}

#[test]
fn test_infer_release_kind_from_name_hints_selects_socket_alias() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false),
        (1usize, Some(KfuncRefKind::Socket), false, false),
    ];
    assert_eq!(
        infer_release_kind_from_name_hints("foo_put_sock_ref", &candidates),
        Some(KfuncRefKind::Socket)
    );
}

#[test]
fn test_infer_release_kind_from_name_hints_rejects_ambiguous_hints() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false),
        (1usize, Some(KfuncRefKind::Cgroup), false, false),
    ];
    assert_eq!(
        infer_release_kind_from_name_hints("foo_task_cgroup_release", &candidates),
        None
    );
}

#[test]
fn test_infer_release_kind_from_name_hints_requires_matching_candidates() {
    let candidates = vec![(0usize, Some(KfuncRefKind::Cgroup), false, false)];
    assert_eq!(
        infer_release_kind_from_name_hints("foo_task_release", &candidates),
        None
    );
}

#[test]
fn test_infer_release_kind_from_named_inputs_selects_unique_kind() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), true, false),
        (1usize, Some(KfuncRefKind::Cgroup), false, false),
    ];
    assert_eq!(
        infer_release_kind_from_named_inputs(&candidates),
        Some(KfuncRefKind::Task)
    );
}

#[test]
fn test_infer_release_kind_from_named_inputs_prefers_non_const() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), true, true),
        (1usize, Some(KfuncRefKind::Cgroup), true, false),
        (2usize, Some(KfuncRefKind::Task), false, false),
    ];
    assert_eq!(
        infer_release_kind_from_named_inputs(&candidates),
        Some(KfuncRefKind::Cgroup)
    );
}

#[test]
fn test_infer_release_kind_from_named_inputs_rejects_ambiguous_kind() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), true, false),
        (1usize, Some(KfuncRefKind::Cgroup), true, false),
    ];
    assert_eq!(infer_release_kind_from_named_inputs(&candidates), None);
}

#[test]
fn test_infer_release_kind_from_named_inputs_requires_named_inputs() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false),
        (1usize, Some(KfuncRefKind::Task), false, false),
    ];
    assert_eq!(infer_release_kind_from_named_inputs(&candidates), None);
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
fn test_infer_unique_release_kind_preferring_non_out_selects_non_out_kind() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false, true),
        (1usize, Some(KfuncRefKind::Cgroup), false, false, false),
    ];
    assert_eq!(
        infer_unique_release_kind_preferring_non_out(&candidates),
        Some(KfuncRefKind::Cgroup)
    );
}

#[test]
fn test_infer_unique_release_kind_preferring_non_out_falls_back_to_all() {
    let candidates = vec![(0usize, Some(KfuncRefKind::Task), false, false, true)];
    assert_eq!(
        infer_unique_release_kind_preferring_non_out(&candidates),
        Some(KfuncRefKind::Task)
    );
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
fn test_infer_unique_release_arg_from_kind_preferring_non_out_selects_non_out() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false, true),
        (1usize, Some(KfuncRefKind::Task), false, false, false),
    ];
    assert_eq!(
        infer_unique_release_arg_from_kind_preferring_non_out(KfuncRefKind::Task, &candidates),
        Some(1)
    );
}

#[test]
fn test_infer_unique_release_arg_from_kind_preferring_non_out_falls_back_to_all() {
    let candidates = vec![(0usize, Some(KfuncRefKind::Task), false, false, true)];
    assert_eq!(
        infer_unique_release_arg_from_kind_preferring_non_out(KfuncRefKind::Task, &candidates),
        Some(0)
    );
}

#[test]
fn test_filter_release_kind_preferring_non_out_accepts_when_no_non_out_refs() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false, true),
        (1usize, None, false, false, false),
    ];
    assert_eq!(
        filter_release_kind_preferring_non_out(KfuncRefKind::Task, &candidates),
        Some(KfuncRefKind::Task)
    );
}

#[test]
fn test_filter_release_kind_preferring_non_out_accepts_matching_non_out_kind() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false, true),
        (1usize, Some(KfuncRefKind::Task), false, false, false),
        (2usize, Some(KfuncRefKind::Cgroup), false, false, false),
    ];
    assert_eq!(
        filter_release_kind_preferring_non_out(KfuncRefKind::Task, &candidates),
        Some(KfuncRefKind::Task)
    );
}

#[test]
fn test_filter_release_kind_preferring_non_out_rejects_out_only_kind() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false, true),
        (1usize, Some(KfuncRefKind::Cgroup), false, false, false),
    ];
    assert_eq!(
        filter_release_kind_preferring_non_out(KfuncRefKind::Task, &candidates),
        None
    );
}

#[test]
fn test_infer_release_kind_from_arg_index_selects_kind() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false),
        (1usize, Some(KfuncRefKind::Cgroup), false, false),
    ];
    assert_eq!(
        infer_release_kind_from_arg_index(Some(1), &candidates),
        Some(KfuncRefKind::Cgroup)
    );
}

#[test]
fn test_infer_release_kind_from_arg_index_rejects_unknown_kind() {
    let candidates = vec![(0usize, None, false, false)];
    assert_eq!(
        infer_release_kind_from_arg_index(Some(0), &candidates),
        None
    );
}

#[test]
fn test_release_arg_index_matches_expected_kind() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false),
        (1usize, Some(KfuncRefKind::Cgroup), false, false),
    ];
    assert!(release_arg_index_matches_expected_kind(
        0,
        KfuncRefKind::Task,
        &candidates
    ));
    assert!(!release_arg_index_matches_expected_kind(
        1,
        KfuncRefKind::Task,
        &candidates
    ));
}

#[test]
fn test_release_arg_index_matches_expected_kind_allows_unknown_kind() {
    let candidates = vec![(0usize, None, false, false)];
    assert!(release_arg_index_matches_expected_kind(
        0,
        KfuncRefKind::Task,
        &candidates
    ));
}

#[test]
fn test_fallback_release_arg_index_from_arg0_accepts_matching_kind() {
    assert_eq!(
        fallback_release_arg_index_from_arg0(KfuncRefKind::Task, Some(KfuncRefKind::Task)),
        Some(0)
    );
}

#[test]
fn test_fallback_release_arg_index_from_arg0_accepts_unknown_kind() {
    assert_eq!(
        fallback_release_arg_index_from_arg0(KfuncRefKind::Task, None),
        Some(0)
    );
}

#[test]
fn test_fallback_release_arg_index_from_arg0_rejects_mismatched_kind() {
    assert_eq!(
        fallback_release_arg_index_from_arg0(KfuncRefKind::Task, Some(KfuncRefKind::Cgroup)),
        None
    );
}

#[test]
fn test_fallback_release_arg_index_from_arg0_preferring_non_out_delegates() {
    let candidates = vec![(0usize, Some(KfuncRefKind::Task), false, false, false)];
    assert_eq!(
        fallback_release_arg_index_from_arg0_preferring_non_out(
            KfuncRefKind::Task,
            Some(KfuncRefKind::Task),
            false,
            &candidates,
        ),
        Some(0)
    );
}

#[test]
fn test_fallback_release_arg_index_from_arg0_preferring_non_out_rejects_named_out_arg0() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false, true),
        (1usize, Some(KfuncRefKind::Task), false, false, false),
    ];
    assert_eq!(
        fallback_release_arg_index_from_arg0_preferring_non_out(
            KfuncRefKind::Task,
            Some(KfuncRefKind::Task),
            true,
            &candidates,
        ),
        None
    );
}

#[test]
fn test_fallback_release_arg_index_from_arg0_preferring_non_out_allows_without_non_out_match() {
    let candidates = vec![
        (0usize, Some(KfuncRefKind::Task), false, false, true),
        (1usize, Some(KfuncRefKind::Cgroup), false, false, false),
    ];
    assert_eq!(
        fallback_release_arg_index_from_arg0_preferring_non_out(
            KfuncRefKind::Task,
            Some(KfuncRefKind::Task),
            true,
            &candidates,
        ),
        Some(0)
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
fn test_infer_unknown_stack_object_copy_args_from_named_pairs_for_type() {
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

    let inferred = infer_unknown_stack_object_copy_args_from_named_pairs_for_type(
        &type_args,
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(
        inferred.len(),
        2,
        "named in/out fallback should infer copy-like transfers without transfer-name hints"
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
fn test_infer_unknown_stack_object_copy_args_from_named_pairs_requires_unique_source() {
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
        UnknownStackObjectArgInfo {
            arg_idx: 2,
            type_name: "bpf_wq".to_string(),
            named_out: true,
            named_in: false,
        },
    ];
    let type_args: Vec<&UnknownStackObjectArgInfo> = args.iter().collect();

    assert!(
        infer_unknown_stack_object_copy_args_from_named_pairs_for_type(
            &type_args,
            &std::collections::BTreeSet::new()
        )
        .is_empty(),
        "named in/out fallback should reject ambiguous source selection"
    );
}

#[test]
fn test_infer_unknown_stack_object_copy_args_from_named_pairs_prefers_non_const_destination() {
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
        infer_unknown_stack_object_copy_args_from_named_pairs_for_type(&type_args, &const_args);
    assert_eq!(
        inferred.len(),
        1,
        "named in/out fallback should prefer writable destinations when available"
    );
    let (src, dst) = inferred[0];
    assert_eq!(src.arg_idx, 0);
    assert_eq!(dst.arg_idx, 2);
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

    let inferred = infer_unknown_stack_object_copy_args_for_type(&type_args, &const_args, false);
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

    let inferred = infer_unknown_stack_object_copy_args_for_type(&type_args, &const_args, false);
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
        copies
            .iter()
            .any(|(src, dst)| src.arg_idx == 0 && dst.arg_idx == 1 && src.type_name == "bpf_wq")
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
        copies
            .iter()
            .any(|(src, dst)| src.arg_idx == 0 && dst.arg_idx == 1 && src.type_name == "bpf_wq")
    );
    assert!(
        copies
            .iter()
            .any(|(src, dst)| src.arg_idx == 0 && dst.arg_idx == 2 && src.type_name == "bpf_wq")
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
fn test_infer_unknown_stack_object_init_arg_from_named_out_fallback_selects_unique_out() {
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
            named_in: false,
        },
    ];
    let selected = infer_unknown_stack_object_init_arg_from_named_out_fallback(&args)
        .expect("expected unique named-out arg to identify init fallback target");
    assert_eq!(selected.arg_idx, 0);
}

#[test]
fn test_infer_unknown_stack_object_init_arg_from_named_out_fallback_rejects_named_in() {
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
    assert!(
        infer_unknown_stack_object_init_arg_from_named_out_fallback(&args).is_none(),
        "init fallback should not apply when named-in stack-object args exist"
    );
}

#[test]
fn test_infer_unknown_stack_object_init_arg_from_named_out_fallback_requires_unique_out() {
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
    assert!(
        infer_unknown_stack_object_init_arg_from_named_out_fallback(&args).is_none(),
        "init fallback should require a unique named-out stack-object arg"
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
