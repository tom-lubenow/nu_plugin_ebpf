use super::*;

fn make_test_service() -> KernelBtf {
    KernelBtf {
        tracefs_events_path: None,
        available_filter_functions_path: None,
        tracepoint_cache: RwLock::new(HashMap::new()),
        function_cache: RwLock::new(None),
        pt_regs_cache: RwLock::new(None),
        raw_type_size_cache: RwLock::new(None),
        raw_pointer_target_cache: RwLock::new(None),
        trampoline_layout_cache: RwLock::new(HashMap::new()),
        struct_ops_layout_cache: RwLock::new(HashMap::new()),
        kfunc_nullable_arg_cache: RwLock::new(None),
        kfunc_const_pointer_arg_cache: RwLock::new(None),
        kfunc_user_pointer_arg_cache: RwLock::new(None),
        kfunc_stack_pointer_arg_cache: RwLock::new(None),
        kfunc_kernel_pointer_arg_cache: RwLock::new(None),
        kfunc_pointer_ref_family_cache: RwLock::new(None),
        kfunc_return_ref_family_cache: RwLock::new(None),
        kfunc_release_ref_arg_index_cache: RwLock::new(None),
        kfunc_known_const_scalar_arg_cache: RwLock::new(None),
        kfunc_positive_scalar_arg_cache: RwLock::new(None),
        kfunc_pointer_size_arg_cache: RwLock::new(None),
        kfunc_stack_slot_base_arg_cache: RwLock::new(None),
        kfunc_out_pointer_arg_cache: RwLock::new(None),
        kfunc_in_pointer_arg_cache: RwLock::new(None),
        kfunc_stack_object_arg_cache: RwLock::new(None),
        kfunc_pointer_fixed_size_cache: RwLock::new(None),
        kfunc_signature_hint_cache: RwLock::new(None),
    }
}

#[test]
fn test_parse_field_line() {
    let service = make_test_service();

    // Test integer field
    let field = service
        .parse_field_line("field:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;")
        .unwrap();
    assert_eq!(field.name, "__syscall_nr");
    assert_eq!(field.offset, 8);
    assert_eq!(field.size, 4);
    assert!(matches!(
        field.type_info,
        TypeInfo::Int {
            size: 4,
            signed: true
        }
    ));

    // Test pointer field
    let field = service
        .parse_field_line("field:const char * filename;\toffset:24;\tsize:8;\tsigned:0;")
        .unwrap();
    assert_eq!(field.name, "filename");
    assert_eq!(field.offset, 24);
    assert!(field.type_info.is_ptr());

    // Test array field
    let field = service
        .parse_field_line("field:unsigned long args[6];\toffset:16;\tsize:48;\tsigned:0;")
        .unwrap();
    assert_eq!(field.name, "args");
    assert_eq!(field.size, 48);
    assert!(matches!(field.type_info, TypeInfo::Array { len: 6, .. }));
}

#[test]
fn test_parse_format_file() {
    let service = make_test_service();

    let content = r#"name: sys_enter_openat
ID: 633
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char * filename;    offset:24;      size:8; signed:0;
        field:int flags;        offset:32;      size:8; signed:0;
        field:umode_t mode;     offset:40;      size:8; signed:0;
"#;

    let ctx = service
        .parse_format_file(content, "syscalls", "sys_enter_openat")
        .unwrap();

    assert_eq!(ctx.category, "syscalls");
    assert_eq!(ctx.name, "sys_enter_openat");

    // Should have 5 non-common fields
    assert_eq!(ctx.fields.len(), 5);

    // Check specific fields
    let syscall_nr = ctx.get_field("__syscall_nr").unwrap();
    assert_eq!(syscall_nr.offset, 8);

    let filename = ctx.get_field("filename").unwrap();
    assert_eq!(filename.offset, 24);
    assert!(filename.type_info.is_ptr());
}

#[test]
fn test_wellknown_sys_enter() {
    let ctx = TracepointContext::sys_enter("sys_enter_openat");
    assert_eq!(ctx.category, "syscalls");
    assert!(ctx.has_field("id"));
    assert!(ctx.has_field("args"));
}

#[test]
fn test_edit_distance() {
    // Identical strings
    assert_eq!(KernelBtf::edit_distance("hello", "hello"), 0);

    // Single character difference
    assert_eq!(KernelBtf::edit_distance("hello", "hallo"), 1);

    // Typo: transposition-like (two edits in edit distance)
    assert_eq!(KernelBtf::edit_distance("sys_clone", "sys_claone"), 1);

    // Missing character
    assert_eq!(KernelBtf::edit_distance("sys_read", "sys_rea"), 1);

    // Extra character
    assert_eq!(KernelBtf::edit_distance("sys_read", "sys_readd"), 1);

    // Completely different
    assert!(KernelBtf::edit_distance("sys_read", "do_fork") > 5);

    // Empty strings
    assert_eq!(KernelBtf::edit_distance("", "abc"), 3);
    assert_eq!(KernelBtf::edit_distance("abc", ""), 3);
}

#[test]
fn test_check_function_graceful_degradation() {
    let service = make_test_service();
    // When function list is not available, should return CannotValidate
    assert_eq!(
        service.check_function("any_function"),
        FunctionCheckResult::CannotValidate
    );
}

#[test]
fn test_kfunc_nullable_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_pointer_arg_is_nullable("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_pointer_arg_is_nullable("definitely_not_a_kfunc", 1));
}

#[test]
fn test_kfunc_user_pointer_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_pointer_arg_requires_user("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_pointer_arg_requires_user("definitely_not_a_kfunc", 3));
}

#[test]
fn test_kfunc_stack_pointer_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_pointer_arg_requires_stack("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_pointer_arg_requires_stack("definitely_not_a_kfunc", 3));
}

#[test]
fn test_kfunc_kernel_pointer_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_pointer_arg_requires_kernel("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_pointer_arg_requires_kernel("definitely_not_a_kfunc", 3));
}

#[test]
fn test_kfunc_pointer_ref_family_query_graceful_without_btf() {
    let service = make_test_service();
    assert_eq!(
        service.kfunc_pointer_arg_ref_family("definitely_not_a_kfunc", 0),
        None
    );
    assert_eq!(
        service.kfunc_pointer_arg_ref_family("definitely_not_a_kfunc", 3),
        None
    );
}

#[test]
fn test_kfunc_return_ref_family_query_graceful_without_btf() {
    let service = make_test_service();
    assert_eq!(
        service.kfunc_return_ref_family("definitely_not_a_kfunc"),
        None
    );
}

#[test]
fn test_kfunc_release_ref_arg_index_query_graceful_without_btf() {
    let service = make_test_service();
    assert_eq!(
        service.kfunc_release_ref_arg_index("definitely_not_a_kfunc"),
        None
    );
}

#[test]
fn test_kfunc_signature_hint_query_graceful_without_btf() {
    let service = make_test_service();
    assert_eq!(
        service.kfunc_signature_hint("__nu_plugin_ebpf_missing_kfunc__"),
        None
    );
}

#[test]
fn test_kfunc_known_const_scalar_arg_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_scalar_arg_requires_known_const("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_scalar_arg_requires_known_const("definitely_not_a_kfunc", 3));
}

#[test]
fn test_kfunc_positive_scalar_arg_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_scalar_arg_requires_positive("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_scalar_arg_requires_positive("definitely_not_a_kfunc", 3));
}

#[test]
fn test_kfunc_pointer_size_arg_query_graceful_without_btf() {
    let service = make_test_service();
    assert_eq!(
        service.kfunc_pointer_arg_size_arg("definitely_not_a_kfunc", 0),
        None
    );
    assert_eq!(
        service.kfunc_pointer_arg_size_arg("definitely_not_a_kfunc", 2),
        None
    );
}

#[test]
fn test_kfunc_pointer_fixed_size_query_graceful_without_btf() {
    let service = make_test_service();
    assert_eq!(
        service.kfunc_pointer_arg_fixed_size("definitely_not_a_kfunc", 0),
        None
    );
    assert_eq!(
        service.kfunc_pointer_arg_fixed_size("definitely_not_a_kfunc", 2),
        None
    );
}

#[test]
fn test_kfunc_stack_slot_base_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_pointer_arg_requires_stack_slot_base("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_pointer_arg_requires_stack_slot_base("definitely_not_a_kfunc", 2));
}

#[test]
fn test_kfunc_named_out_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_pointer_arg_is_named_out("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_pointer_arg_is_named_out("definitely_not_a_kfunc", 2));
}

#[test]
fn test_kfunc_named_in_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_pointer_arg_is_named_in("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_pointer_arg_is_named_in("definitely_not_a_kfunc", 2));
}

#[test]
fn test_kfunc_const_pointer_query_graceful_without_btf() {
    let service = make_test_service();
    assert!(!service.kfunc_pointer_arg_is_const("definitely_not_a_kfunc", 0));
    assert!(!service.kfunc_pointer_arg_is_const("definitely_not_a_kfunc", 2));
}

#[test]
fn test_kfunc_stack_object_type_query_graceful_without_btf() {
    let service = make_test_service();
    assert_eq!(
        service.kfunc_pointer_arg_stack_object_type_name("definitely_not_a_kfunc", 0),
        None
    );
    assert_eq!(
        service.kfunc_pointer_arg_stack_object_type_name("definitely_not_a_kfunc", 2),
        None
    );
}

#[test]
fn test_kfunc_stack_object_type_id_query_graceful_without_btf() {
    let service = make_test_service();
    assert_eq!(
        service.kfunc_pointer_arg_stack_object_type_id("definitely_not_a_kfunc", 0),
        None
    );
    assert_eq!(
        service.kfunc_pointer_arg_stack_object_type_id("definitely_not_a_kfunc", 2),
        None
    );
}

#[test]
fn test_kfunc_size_param_base_name() {
    assert_eq!(
        KernelBtf::kfunc_size_param_base_name("buf__sz"),
        Some("buf")
    );
    assert_eq!(
        KernelBtf::kfunc_size_param_base_name("buffer__szk"),
        Some("buffer")
    );
    assert_eq!(KernelBtf::kfunc_size_param_base_name("size"), None);
    assert_eq!(KernelBtf::kfunc_size_param_base_name("__sz"), None);
    assert_eq!(KernelBtf::kfunc_size_param_base_name("__szk"), None);
}

#[test]
fn test_infer_pointer_ref_family_from_type_name() {
    assert_eq!(
        KernelBtf::infer_pointer_ref_family("task_struct"),
        Some(KfuncPointerRefFamily::Task)
    );
    assert_eq!(
        KernelBtf::infer_pointer_ref_family("cgroup"),
        Some(KfuncPointerRefFamily::Cgroup)
    );
    assert_eq!(
        KernelBtf::infer_pointer_ref_family("bpf_cpumask"),
        Some(KfuncPointerRefFamily::Cpumask)
    );
    assert_eq!(
        KernelBtf::infer_pointer_ref_family("inode"),
        Some(KfuncPointerRefFamily::Inode)
    );
    assert_eq!(
        KernelBtf::infer_pointer_ref_family("file"),
        Some(KfuncPointerRefFamily::File)
    );
    assert_eq!(
        KernelBtf::infer_pointer_ref_family("sock_common"),
        Some(KfuncPointerRefFamily::Socket)
    );
    assert_eq!(
        KernelBtf::infer_pointer_ref_family("bpf_crypto_ctx"),
        Some(KfuncPointerRefFamily::CryptoCtx)
    );
    assert_eq!(KernelBtf::infer_pointer_ref_family("u8"), None);
}

#[test]
fn test_is_stack_object_type_name() {
    assert!(KernelBtf::is_stack_object_type_name("bpf_iter_task"));
    assert!(KernelBtf::is_stack_object_type_name("bpf_dynptr"));
    assert!(KernelBtf::is_stack_object_type_name("bpf_dynptr_kern"));
    assert!(KernelBtf::is_stack_object_type_name("bpf_wq"));
    assert!(KernelBtf::is_stack_object_type_name("bpf_custom_state"));
    assert!(!KernelBtf::is_stack_object_type_name("bpf_cpumask"));
    assert!(!KernelBtf::is_stack_object_type_name("bpf_map"));
    assert!(!KernelBtf::is_stack_object_type_name("bpf_socket"));
    assert!(!KernelBtf::is_stack_object_type_name("task_struct"));
}

#[test]
fn test_is_kernel_pointer_type_name() {
    assert!(KernelBtf::is_kernel_pointer_type_name("task_struct"));
    assert!(KernelBtf::is_kernel_pointer_type_name("bpf_map"));
    assert!(KernelBtf::is_kernel_pointer_type_name("bpf_map_array"));
    assert!(!KernelBtf::is_kernel_pointer_type_name("bpf_iter_task"));
    assert!(!KernelBtf::is_kernel_pointer_type_name("u8"));
}

#[test]
fn test_is_probable_release_kfunc_name() {
    assert!(KernelBtf::is_probable_release_kfunc_name(
        "bpf_task_release"
    ));
    assert!(KernelBtf::is_probable_release_kfunc_name("bpf_put_file"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_put_bar"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_drop"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_free"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_destroy"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_cleanup"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_deinit"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_fini"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_delete"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_detach"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_close"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_unref"));
    assert!(KernelBtf::is_probable_release_kfunc_name("foo_obj_dec"));
    assert!(!KernelBtf::is_probable_release_kfunc_name(
        "bpf_task_acquire"
    ));
    assert!(!KernelBtf::is_probable_release_kfunc_name("foo_obj_inc"));
}

#[test]
fn test_infer_release_arg_index_from_family_args_prefers_non_out() {
    let family_args = vec![(0usize, true, false), (1usize, false, false)];
    assert_eq!(
        KernelBtf::infer_release_arg_index_from_family_args(&family_args),
        Some(1)
    );
}

#[test]
fn test_infer_release_arg_index_from_family_args_falls_back_to_single_out() {
    let family_args = vec![(0usize, true, false)];
    assert_eq!(
        KernelBtf::infer_release_arg_index_from_family_args(&family_args),
        Some(0)
    );
}

#[test]
fn test_infer_release_arg_index_from_family_args_rejects_ambiguous_non_out() {
    let family_args = vec![(0usize, false, false), (1usize, false, false)];
    assert_eq!(
        KernelBtf::infer_release_arg_index_from_family_args(&family_args),
        None
    );
}

#[test]
fn test_infer_release_arg_index_from_family_args_prefers_writable() {
    let family_args = vec![(0usize, false, true), (1usize, false, false)];
    assert_eq!(
        KernelBtf::infer_release_arg_index_from_family_args(&family_args),
        Some(1)
    );
}

#[test]
fn test_is_probable_out_param_name() {
    assert!(KernelBtf::is_probable_out_param_name("out"));
    assert!(KernelBtf::is_probable_out_param_name("out_task"));
    assert!(KernelBtf::is_probable_out_param_name("task_out"));
    assert!(KernelBtf::is_probable_out_param_name("dst"));
    assert!(KernelBtf::is_probable_out_param_name("dst_ctx"));
    assert!(KernelBtf::is_probable_out_param_name("ctx_dst"));
    assert!(KernelBtf::is_probable_out_param_name("to"));
    assert!(KernelBtf::is_probable_out_param_name("task_to"));
    assert!(KernelBtf::is_probable_out_param_name("to_task"));
    assert!(KernelBtf::is_probable_out_param_name("new"));
    assert!(KernelBtf::is_probable_out_param_name("new_ctx"));
    assert!(KernelBtf::is_probable_out_param_name("ctx_new"));
    assert!(KernelBtf::is_probable_out_param_name("dup"));
    assert!(KernelBtf::is_probable_out_param_name("dup_ctx"));
    assert!(KernelBtf::is_probable_out_param_name("ctx_dup"));
    assert!(KernelBtf::is_probable_out_param_name("err"));
    assert!(KernelBtf::is_probable_out_param_name("user_err"));
    assert!(KernelBtf::is_probable_out_param_name("result"));
    assert!(KernelBtf::is_probable_out_param_name("ctx_result"));
    assert!(KernelBtf::is_probable_out_param_name("retval"));
    assert!(KernelBtf::is_probable_out_param_name("ctx_retval"));
    assert!(KernelBtf::is_probable_out_param_name("clone__uninit"));
    assert!(KernelBtf::is_probable_out_param_name("ptr_uninit"));
    assert!(!KernelBtf::is_probable_out_param_name("task"));
    assert!(!KernelBtf::is_probable_out_param_name("flags"));
}

#[test]
fn test_is_probable_in_param_name() {
    assert!(KernelBtf::is_probable_in_param_name("in"));
    assert!(KernelBtf::is_probable_in_param_name("in_task"));
    assert!(KernelBtf::is_probable_in_param_name("task_in"));
    assert!(KernelBtf::is_probable_in_param_name("src"));
    assert!(KernelBtf::is_probable_in_param_name("src_ctx"));
    assert!(KernelBtf::is_probable_in_param_name("ctx_src"));
    assert!(KernelBtf::is_probable_in_param_name("from"));
    assert!(KernelBtf::is_probable_in_param_name("from_task"));
    assert!(KernelBtf::is_probable_in_param_name("task_from"));
    assert!(KernelBtf::is_probable_in_param_name("old"));
    assert!(KernelBtf::is_probable_in_param_name("old_task"));
    assert!(KernelBtf::is_probable_in_param_name("task_old"));
    assert!(KernelBtf::is_probable_in_param_name("orig"));
    assert!(KernelBtf::is_probable_in_param_name("orig_task"));
    assert!(KernelBtf::is_probable_in_param_name("task_orig"));
    assert!(!KernelBtf::is_probable_in_param_name("dst"));
    assert!(!KernelBtf::is_probable_in_param_name("out"));
    assert!(!KernelBtf::is_probable_in_param_name("flags"));
}

fn push_u16(buf: &mut Vec<u8>, value: u16, endianness: BtfEndianness) {
    match endianness {
        BtfEndianness::Little => buf.extend_from_slice(&value.to_le_bytes()),
        BtfEndianness::Big => buf.extend_from_slice(&value.to_be_bytes()),
    }
}

#[test]
fn test_validate_fexit_target_rejects_aggregate_return_candidate() {
    let candidate = ["__jump_label_patch", "__ioapic_read_entry"]
        .into_iter()
        .find(|func_name| {
            matches!(
                KernelBtf::get().function_trampoline_ret(func_name),
                Ok(Some(TrampolineValueSpec {
                    kind: TrampolineValueKind::Aggregate { .. },
                    ..
                }))
            )
        });

    let Some(func_name) = candidate else {
        return;
    };

    let err = KernelBtf::get()
        .validate_fexit_target(func_name)
        .expect_err("aggregate-return fexit target should be rejected early");
    assert!(
        matches!(err, BtfError::KernelBtfError(message) if message.contains("aggregate return"))
    );
}

fn find_struct_ops_callback_candidate() -> Option<(&'static str, &'static str)> {
    for (value_type_name, callback_name) in [
        ("sched_ext_ops", "select_cpu"),
        ("tcp_congestion_ops", "ssthresh"),
        ("tcp_congestion_ops", "cong_avoid"),
        ("tcp_congestion_ops", "init"),
    ] {
        if matches!(
            KernelBtf::get().struct_ops_callback_arg_type_info(value_type_name, callback_name, 0),
            Ok(Some(_))
        ) {
            return Some((value_type_name, callback_name));
        }
    }
    None
}

fn find_struct_ops_named_arg_candidate() -> Option<(&'static str, &'static str, &'static str, usize)>
{
    for (value_type_name, callback_name, arg_name, expected_idx) in [
        ("sched_ext_ops", "select_cpu", "p", 0usize),
        ("sched_ext_ops", "select_cpu", "prev_cpu", 1),
        ("tcp_congestion_ops", "ssthresh", "sk", 0),
        ("tcp_congestion_ops", "cong_avoid", "sk", 0),
        ("tcp_congestion_ops", "init", "sk", 0),
    ] {
        if matches!(
            KernelBtf::get().struct_ops_callback_arg_index_by_name(
                value_type_name,
                callback_name,
                arg_name
            ),
            Ok(Some(idx)) if idx == expected_idx
        ) {
            return Some((value_type_name, callback_name, arg_name, expected_idx));
        }
    }
    None
}

fn find_function_trampoline_named_arg_candidate() -> Option<(&'static str, &'static str, usize)> {
    for (function_name, arg_name, expected_idx) in [
        ("security_file_open", "file", 0usize),
        ("do_close_on_exec", "files", 0),
    ] {
        if matches!(
            KernelBtf::get().function_trampoline_arg_index_by_name(function_name, arg_name),
            Ok(Some(idx)) if idx == expected_idx
        ) {
            return Some((function_name, arg_name, expected_idx));
        }
    }
    None
}

fn find_lsm_hook_named_arg_candidate() -> Option<(&'static str, &'static str, usize)> {
    for (hook_name, arg_name, expected_idx) in [("file_open", "file", 0usize)] {
        if matches!(
            KernelBtf::get().lsm_hook_arg_index_by_name(hook_name, arg_name),
            Ok(Some(idx)) if idx == expected_idx
        ) {
            return Some((hook_name, arg_name, expected_idx));
        }
    }
    None
}

#[test]
fn test_tp_btf_arg_type_info_skips_hidden_context_slot() {
    let callable_name = KernelBtf::tp_btf_type_name("sys_enter");
    let Ok(Some(raw_visible_arg)) =
        KernelBtf::get().function_trampoline_arg_type_info(&callable_name, 1)
    else {
        return;
    };
    let user_visible_arg = KernelBtf::get()
        .tp_btf_arg_type_info("sys_enter", 0)
        .expect("tp_btf arg query should succeed")
        .expect("tp_btf sys_enter arg0 should exist");

    assert_eq!(
        format!("{user_visible_arg:?}"),
        format!("{raw_visible_arg:?}")
    );
}

#[test]
fn test_tp_btf_arg_index_by_name_skips_hidden_context_slot() {
    let callable_name = KernelBtf::tp_btf_type_name("sys_enter");
    let Ok(Some(raw_visible_idx)) =
        KernelBtf::get().function_trampoline_arg_index_by_name(&callable_name, "regs")
    else {
        return;
    };
    let user_visible_idx = KernelBtf::get()
        .tp_btf_arg_index_by_name("sys_enter", "regs")
        .expect("tp_btf arg index query should succeed")
        .expect("tp_btf sys_enter regs arg should exist");

    assert_eq!(
        raw_visible_idx,
        user_visible_idx + KernelBtf::TP_BTF_HIDDEN_ARG_COUNT
    );
    assert_eq!(user_visible_idx, 0);
}

#[test]
fn test_tp_btf_arg_field_skips_hidden_context_slot() {
    let callable_name = KernelBtf::tp_btf_type_name("sys_enter");
    let field_path = [TrampolineFieldSelector::Field("orig_ax".to_string())];
    let Ok(Some(raw_visible_projection)) =
        KernelBtf::get().function_trampoline_arg_field(&callable_name, 1, &field_path)
    else {
        return;
    };
    let user_visible_projection = KernelBtf::get()
        .tp_btf_arg_field("sys_enter", 0, &field_path)
        .expect("tp_btf field query should succeed")
        .expect("tp_btf sys_enter regs.orig_ax should exist");

    assert_eq!(
        format!("{user_visible_projection:?}"),
        format!("{raw_visible_projection:?}")
    );
}

#[test]
fn test_struct_ops_callback_arg_type_info_resolves_candidate() {
    let Some((value_type_name, callback_name)) = find_struct_ops_callback_candidate() else {
        return;
    };

    let arg = KernelBtf::get()
        .struct_ops_callback_arg_type_info(value_type_name, callback_name, 0)
        .expect("struct_ops callback arg query should succeed")
        .expect("struct_ops callback arg0 should exist");

    assert!(matches!(arg, TypeInfo::Ptr { .. } | TypeInfo::Int { .. }));
}

#[test]
fn test_struct_ops_callback_arg_index_by_name_resolves_candidate() {
    let Some((value_type_name, callback_name, arg_name, expected_idx)) =
        find_struct_ops_named_arg_candidate()
    else {
        return;
    };

    let arg_idx = KernelBtf::get()
        .struct_ops_callback_arg_index_by_name(value_type_name, callback_name, arg_name)
        .expect("struct_ops callback arg index query should succeed")
        .expect("named struct_ops callback arg should exist");

    assert_eq!(arg_idx, expected_idx);
}

#[test]
fn test_function_trampoline_arg_index_by_name_resolves_candidate() {
    let Some((function_name, arg_name, expected_idx)) =
        find_function_trampoline_named_arg_candidate()
    else {
        return;
    };

    let arg_idx = KernelBtf::get()
        .function_trampoline_arg_index_by_name(function_name, arg_name)
        .expect("function trampoline arg index query should succeed")
        .expect("named function trampoline arg should exist");

    assert_eq!(arg_idx, expected_idx);
}

#[test]
fn test_lsm_hook_arg_index_by_name_resolves_candidate() {
    let Some((hook_name, arg_name, expected_idx)) = find_lsm_hook_named_arg_candidate() else {
        return;
    };

    let arg_idx = KernelBtf::get()
        .lsm_hook_arg_index_by_name(hook_name, arg_name)
        .expect("lsm hook arg index query should succeed")
        .expect("named lsm hook arg should exist");

    assert_eq!(arg_idx, expected_idx);
}

#[test]
fn test_function_trampoline_arg_infos_include_names_when_available() {
    let Some((function_name, arg_name, expected_idx)) =
        find_function_trampoline_named_arg_candidate()
    else {
        return;
    };

    let infos = KernelBtf::get()
        .function_trampoline_arg_infos(function_name)
        .expect("function trampoline arg infos query should succeed");
    let info = infos
        .iter()
        .find(|info| info.name.as_deref() == Some(arg_name))
        .expect("named function trampoline arg info should exist");

    assert_eq!(info.index, expected_idx);
    assert!(info.value.is_some());
}

#[test]
fn test_tp_btf_arg_infos_skip_hidden_context_slot() {
    let callable_name = KernelBtf::tp_btf_type_name("sys_enter");
    let Ok(Some(_raw_visible_idx)) =
        KernelBtf::get().function_trampoline_arg_index_by_name(&callable_name, "regs")
    else {
        return;
    };

    let infos = KernelBtf::get()
        .tp_btf_arg_infos("sys_enter")
        .expect("tp_btf arg infos query should succeed");
    let regs = infos
        .iter()
        .find(|info| info.name.as_deref() == Some("regs"))
        .expect("tp_btf visible regs arg info should exist");

    assert_eq!(regs.index, 0);
    assert!(regs.value.is_some());
}

#[test]
fn test_struct_ops_callback_arg_infos_include_names_when_available() {
    let Some((value_type_name, callback_name, arg_name, expected_idx)) =
        find_struct_ops_named_arg_candidate()
    else {
        return;
    };

    let infos = KernelBtf::get()
        .struct_ops_callback_arg_infos(value_type_name, callback_name)
        .expect("struct_ops arg infos query should succeed");
    let info = infos
        .iter()
        .find(|info| info.name.as_deref() == Some(arg_name))
        .expect("named struct_ops arg info should exist");

    assert_eq!(info.index, expected_idx);
    assert!(info.value.is_some());
}

#[test]
fn test_struct_ops_callback_ret_type_info_resolves_candidate() {
    for (value_type_name, callback_name) in [
        ("sched_ext_ops", "select_cpu"),
        ("tcp_congestion_ops", "ssthresh"),
        ("tcp_congestion_ops", "cong_avoid"),
        ("tcp_congestion_ops", "init"),
    ] {
        let Ok(ret_ty) =
            KernelBtf::get().struct_ops_callback_ret_type_info(value_type_name, callback_name)
        else {
            continue;
        };
        assert!(matches!(
            ret_ty,
            None | Some(TypeInfo::Int { .. })
                | Some(TypeInfo::Ptr { .. })
                | Some(TypeInfo::Struct { .. })
                | Some(TypeInfo::Array { .. })
                | Some(TypeInfo::Void)
                | Some(TypeInfo::Unknown)
        ));
        return;
    }
}

#[test]
fn test_function_trampoline_arg_field_resolves_pointer_hop() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "security_file_open",
            0,
            &[
                TrampolineFieldSelector::Field("f_inode".to_string()),
                TrampolineFieldSelector::Field("i_ino".to_string()),
            ],
        )
        .expect("security_file_open pointer-hop field path should resolve")
        .expect("security_file_open arg0 should exist");

    assert_eq!(projection.path.len(), 2);
    assert!(matches!(
        projection.path[0].type_info,
        TypeInfo::Ptr { is_user: false, .. }
    ));
    assert!(matches!(projection.type_info, TypeInfo::Int { .. }));
}

#[test]
fn test_function_trampoline_arg_field_resolves_array_index() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "wake_up_new_task",
            0,
            &[
                TrampolineFieldSelector::Field("comm".to_string()),
                TrampolineFieldSelector::Index(0),
            ],
        )
        .expect("wake_up_new_task array field path should resolve")
        .expect("wake_up_new_task arg0 should exist");

    assert_eq!(projection.path.len(), 2);
    assert!(matches!(
        projection.path[0].type_info,
        TypeInfo::Array { len: 16, .. }
    ));
    assert!(matches!(
        projection.type_info,
        TypeInfo::Int { size: 1, .. }
    ));
}

#[test]
fn test_function_trampoline_arg_field_resolves_bitfield_leaf() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "wake_up_new_task",
            0,
            &[
                TrampolineFieldSelector::Field("uclamp_req".to_string()),
                TrampolineFieldSelector::Index(0),
                TrampolineFieldSelector::Field("value".to_string()),
            ],
        )
        .expect("wake_up_new_task bitfield projection should resolve")
        .expect("wake_up_new_task arg0 should exist");

    assert_eq!(projection.path.len(), 3);
    assert_eq!(projection.path[2].offset_bytes, 0);
    assert_eq!(
        projection.path[2].bitfield,
        Some(TrampolineBitfieldInfo {
            bit_offset: 0,
            bit_size: 11,
        })
    );
    assert!(matches!(
        projection.type_info,
        TypeInfo::Int {
            size: 4,
            signed: false
        }
    ));
}

#[test]
fn test_function_trampoline_arg_field_struct_leaf_preserves_member_layout() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "security_file_open",
            0,
            &[TrampolineFieldSelector::Field("f_path".to_string())],
        )
        .expect("security_file_open f_path projection should resolve")
        .expect("security_file_open arg0.f_path should exist");

    let TypeInfo::Struct { size, fields, .. } = projection.type_info else {
        panic!("expected security_file_open arg0.f_path to resolve to a struct");
    };

    assert_eq!(size, 16);
    assert!(fields.len() >= 2);
    assert_eq!(fields[0].name, "mnt");
    assert!(matches!(fields[0].type_info, TypeInfo::Ptr { .. }));
    assert_eq!(fields[0].offset, 0);
    assert_eq!(fields[1].name, "dentry");
    assert!(matches!(fields[1].type_info, TypeInfo::Ptr { .. }));
    assert_eq!(fields[1].offset, 8);
}

#[test]
fn test_function_trampoline_arg_field_pointer_target_keeps_representable_members() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "security_file_open",
            0,
            &[TrampolineFieldSelector::Field("f_inode".to_string())],
        )
        .expect("security_file_open f_inode projection should resolve")
        .expect("security_file_open arg0.f_inode should exist");

    let TypeInfo::Ptr { target, .. } = projection.type_info else {
        panic!("expected security_file_open arg0.f_inode to resolve to a pointer");
    };
    let TypeInfo::Struct { fields, .. } = target.as_ref() else {
        panic!("expected security_file_open arg0.f_inode target to be a struct");
    };

    assert!(
        fields.iter().any(|field| {
            field.name == "i_ino" && matches!(field.type_info, TypeInfo::Int { size: 8, .. })
        }),
        "expected typed inode projection to preserve i_ino"
    );
}

#[test]
fn test_kernel_type_field_projection_resolves_deeper_pointer_target_member() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "security_file_open",
            0,
            &[
                TrampolineFieldSelector::Field("f_inode".to_string()),
                TrampolineFieldSelector::Field("i_sb".to_string()),
            ],
        )
        .expect("security_file_open f_inode.i_sb projection should resolve")
        .expect("security_file_open arg0.f_inode.i_sb should exist");

    let TypeInfo::Ptr { target, .. } = projection.type_info else {
        panic!("expected security_file_open arg0.f_inode.i_sb to resolve to a pointer");
    };
    let type_id = target
        .kernel_btf_type_id()
        .expect("expected super_block target to preserve kernel BTF type id");

    let nested = KernelBtf::get()
        .kernel_type_field_projection(
            type_id,
            &[TrampolineFieldSelector::Field("s_flags".to_string())],
        )
        .expect("expected kernel type field projection for super_block.s_flags");

    assert_eq!(nested.path.len(), 1);
    assert!(matches!(
        nested.type_info,
        TypeInfo::Int { size: 4 | 8, .. }
    ));
}

#[test]
fn test_kernel_named_type_field_projection_resolves_common_member() {
    let arg_info = KernelBtf::get()
        .function_trampoline_arg_type_info("security_file_open", 0)
        .expect("expected security_file_open arg0 type info")
        .expect("expected security_file_open arg0 to exist");
    let TypeInfo::Ptr { target, .. } = arg_info else {
        panic!("expected security_file_open arg0 to resolve to a pointer");
    };
    let type_id = target
        .kernel_btf_type_id()
        .expect("expected file target to preserve kernel BTF type id");

    let projection = KernelBtf::get()
        .kernel_named_type_field_projection(
            "file",
            &[TrampolineFieldSelector::Field("f_inode".to_string())],
        )
        .expect("expected file.f_inode projection by named type");
    let by_type_id = KernelBtf::get()
        .kernel_type_field_projection(
            type_id,
            &[TrampolineFieldSelector::Field("f_inode".to_string())],
        )
        .expect("expected file.f_inode projection by type id");

    assert_eq!(projection.path.len(), 1);
    assert_eq!(
        projection.path[0].offset_bytes,
        by_type_id.path[0].offset_bytes
    );
    assert!(matches!(projection.type_info, TypeInfo::Ptr { .. }));
}

#[test]
fn test_kernel_named_type_field_projection_resolves_anonymous_union_member() {
    let projection = KernelBtf::get()
        .kernel_named_type_field_projection(
            "bpf_iter_meta",
            &[TrampolineFieldSelector::Field("seq".to_string())],
        )
        .expect("expected bpf_iter_meta.seq projection through anonymous union");

    assert_eq!(projection.path.len(), 1);
    assert_eq!(projection.path[0].offset_bytes, 0);
    assert!(matches!(projection.type_info, TypeInfo::Ptr { .. }));
}

#[test]
fn test_kernel_named_type_info_resolves_common_struct() {
    let info = KernelBtf::get()
        .kernel_named_type_info("file")
        .expect("expected named file type info");
    let TypeInfo::Struct { size, fields, .. } = info else {
        panic!("expected named file type info to resolve to a struct");
    };
    assert!(size >= 40, "unexpected file size: {size}");
    assert!(!fields.is_empty(), "expected representable file fields");
}

#[test]
fn test_kernel_named_type_field_projection_preserves_cgroup_pointer_target_name() {
    let projection = KernelBtf::get()
        .kernel_named_type_field_projection(
            "task_struct",
            &[
                TrampolineFieldSelector::Field("cgroups".to_string()),
                TrampolineFieldSelector::Field("dfl_cgrp".to_string()),
            ],
        )
        .expect("expected task_struct.cgroups.dfl_cgrp projection");

    let TypeInfo::Ptr { target, .. } = projection.type_info else {
        panic!("expected task_struct.cgroups.dfl_cgrp to resolve to a pointer");
    };
    let TypeInfo::Struct {
        name, btf_type_id, ..
    } = target.as_ref()
    else {
        panic!("expected task_struct.cgroups.dfl_cgrp target to resolve to a struct");
    };

    assert_eq!(name, "cgroup");
    assert!(
        btf_type_id.is_some(),
        "expected cgroup target to preserve canonical kernel BTF type id"
    );
}

#[test]
fn test_kernel_named_type_size_bytes_resolves_common_struct() {
    let size = KernelBtf::get()
        .kernel_named_type_size_bytes("file")
        .expect("expected named file type size");
    assert!(size >= 40, "unexpected file size: {size}");
}

#[test]
fn test_kernel_named_enum_info_resolves_sched_ext_flags_if_present() {
    let Ok(info) = KernelBtf::get().kernel_named_enum_info("scx_ops_flags") else {
        return;
    };

    assert!(
        !info.is_signed,
        "expected scx_ops_flags to be an unsigned enum"
    );
    assert!(
        info.entries
            .iter()
            .any(|(name, value)| name == "SCX_OPS_ALL_FLAGS" && (*value as u64) != 0),
        "expected scx_ops_flags to expose SCX_OPS_ALL_FLAGS"
    );
}

#[test]
fn test_function_trampoline_arg_field_resolves_multi_level_pointer_projection() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "do_close_on_exec",
            0,
            &[
                TrampolineFieldSelector::Field("fdt".to_string()),
                TrampolineFieldSelector::Field("fd".to_string()),
                TrampolineFieldSelector::Field("f_inode".to_string()),
                TrampolineFieldSelector::Field("i_ino".to_string()),
            ],
        )
        .expect("do_close_on_exec fdt.fd.f_inode.i_ino projection should resolve")
        .expect("do_close_on_exec arg0.fdt.fd.f_inode.i_ino should exist");

    assert_eq!(projection.path.len(), 5);
    assert_eq!(projection.path[2].offset_bytes, 0);
    assert!(matches!(projection.path[2].type_info, TypeInfo::Ptr { .. }));
    assert!(matches!(
        projection.type_info,
        TypeInfo::Int { size: 8, .. }
    ));
}

#[test]
fn test_function_trampoline_arg_field_resolves_pointer_index_projection() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "do_close_on_exec",
            0,
            &[
                TrampolineFieldSelector::Field("fdt".to_string()),
                TrampolineFieldSelector::Field("fd".to_string()),
                TrampolineFieldSelector::Index(0),
                TrampolineFieldSelector::Field("f_inode".to_string()),
                TrampolineFieldSelector::Field("i_ino".to_string()),
            ],
        )
        .expect("do_close_on_exec fdt.fd.0.f_inode.i_ino projection should resolve")
        .expect("do_close_on_exec arg0.fdt.fd.0.f_inode.i_ino should exist");

    assert_eq!(projection.path.len(), 5);
    assert_eq!(projection.path[2].offset_bytes, 0);
    assert!(matches!(projection.path[2].type_info, TypeInfo::Ptr { .. }));
    assert!(matches!(
        projection.type_info,
        TypeInfo::Int { size: 8, .. }
    ));
}

#[test]
fn test_function_trampoline_arg_type_info_preserves_root_pointer_layout() {
    let type_info = KernelBtf::get()
        .function_trampoline_arg_type_info("do_close_on_exec", 0)
        .expect("do_close_on_exec arg0 type info should resolve")
        .expect("do_close_on_exec arg0 should exist");

    let TypeInfo::Ptr { target, .. } = type_info else {
        panic!("expected do_close_on_exec arg0 to resolve to a pointer");
    };
    let TypeInfo::Struct {
        btf_type_id,
        fields,
        ..
    } = target.as_ref()
    else {
        panic!("expected do_close_on_exec arg0 pointee to be a struct");
    };
    assert!(
        btf_type_id.is_some(),
        "expected root trampoline type to preserve a kernel BTF type id"
    );
    assert!(
        fields.iter().any(|field| field.name == "fdt"),
        "expected files_struct root type to preserve the fdt field"
    );
}

fn push_u32(buf: &mut Vec<u8>, value: u32, endianness: BtfEndianness) {
    match endianness {
        BtfEndianness::Little => buf.extend_from_slice(&value.to_le_bytes()),
        BtfEndianness::Big => buf.extend_from_slice(&value.to_be_bytes()),
    }
}

fn make_minimal_raw_btf_with_type_headers(
    endianness: BtfEndianness,
    type_headers: &[(u32, u32)],
) -> Vec<u8> {
    let hdr_len = 24u32;
    let type_len = (type_headers.len() as u32) * 12;
    let str_off = type_len;
    let str_len = 1u32;

    let mut out = Vec::new();
    push_u16(&mut out, 0xeb9f, endianness);
    out.push(1); // version
    out.push(0); // flags
    push_u32(&mut out, hdr_len, endianness);
    push_u32(&mut out, 0, endianness); // type_off
    push_u32(&mut out, type_len, endianness);
    push_u32(&mut out, str_off, endianness);
    push_u32(&mut out, str_len, endianness);

    for (info, size_type) in type_headers {
        push_u32(&mut out, 0, endianness); // name_off
        push_u32(&mut out, *info, endianness);
        push_u32(&mut out, *size_type, endianness);
    }

    out.push(0); // string section null terminator
    out
}

#[test]
fn test_parse_raw_btf_function_return_type_ids_little_endian() {
    let type_headers = [
        ((12u32 << 24) | 1, 2), // BTF_KIND_FUNC -> proto id 2
        (13u32 << 24, 0),       // BTF_KIND_FUNC_PROTO -> void return
    ];
    let raw = make_minimal_raw_btf_with_type_headers(BtfEndianness::Little, &type_headers);
    let parsed = parse_function_return_type_ids_from_raw_btf(&raw)
        .expect("expected return-type map from raw BTF");
    assert_eq!(parsed.get(&1).copied(), Some(0));
}

#[test]
fn test_parse_raw_btf_function_return_type_ids_pointer_return() {
    let type_headers = [
        ((12u32 << 24) | 1, 2), // BTF_KIND_FUNC -> proto id 2
        (13u32 << 24, 3),       // BTF_KIND_FUNC_PROTO -> pointer return type id 3
        (2u32 << 24, 0),        // BTF_KIND_PTR
    ];
    let raw = make_minimal_raw_btf_with_type_headers(BtfEndianness::Little, &type_headers);
    let parsed = parse_function_return_type_ids_from_raw_btf(&raw)
        .expect("expected return-type map from raw BTF");
    assert_eq!(parsed.get(&1).copied(), Some(3));
}

#[test]
fn test_parse_raw_btf_pointer_target_type_ids_little_endian() {
    let type_headers = [
        (4u32 << 24, 8), // BTF_KIND_STRUCT, size 8, vlen 0
        (2u32 << 24, 1), // BTF_KIND_PTR -> struct id 1
    ];
    let raw = make_minimal_raw_btf_with_type_headers(BtfEndianness::Little, &type_headers);
    let parsed = parse_pointer_target_type_ids_from_raw_btf(&raw)
        .expect("expected pointer target map from raw BTF");
    assert_eq!(parsed.get(&2).copied(), Some(1));
    assert_eq!(parsed.get(&1).copied(), None);
}

#[test]
fn test_parse_raw_btf_function_return_type_ids_with_decl_tag() {
    let hdr_len = 24u32;
    let type_len = 12u32 + 20u32 + 16u32;
    let str_off = type_len;
    let str_len = 1u32;

    let mut raw = Vec::new();
    push_u16(&mut raw, 0xeb9f, BtfEndianness::Little);
    raw.push(1); // version
    raw.push(0); // flags
    push_u32(&mut raw, hdr_len, BtfEndianness::Little);
    push_u32(&mut raw, 0, BtfEndianness::Little); // type_off
    push_u32(&mut raw, type_len, BtfEndianness::Little);
    push_u32(&mut raw, str_off, BtfEndianness::Little);
    push_u32(&mut raw, str_len, BtfEndianness::Little);

    // [1] BTF_KIND_DECL_TAG -> type_id 0, payload component_idx=0
    push_u32(&mut raw, 0, BtfEndianness::Little); // name_off
    push_u32(&mut raw, 17u32 << 24, BtfEndianness::Little);
    push_u32(&mut raw, 0, BtfEndianness::Little); // type
    push_u32(&mut raw, 0, BtfEndianness::Little); // component_idx

    // [2] BTF_KIND_FUNC -> proto id 3
    push_u32(&mut raw, 0, BtfEndianness::Little); // name_off
    push_u32(&mut raw, (12u32 << 24) | 1, BtfEndianness::Little);
    push_u32(&mut raw, 3, BtfEndianness::Little);

    // [3] BTF_KIND_FUNC_PROTO -> int return, one int arg
    push_u32(&mut raw, 0, BtfEndianness::Little); // name_off
    push_u32(&mut raw, (13u32 << 24) | 1, BtfEndianness::Little);
    push_u32(&mut raw, 4, BtfEndianness::Little); // ret_type_id
    push_u32(&mut raw, 0, BtfEndianness::Little); // param name_off
    push_u32(&mut raw, 4, BtfEndianness::Little); // param type_id

    raw.push(0); // string section null terminator

    let parsed = parse_function_return_type_ids_from_raw_btf(&raw)
        .expect("expected return-type map from raw BTF with decl tag");
    assert_eq!(parsed.get(&2).copied(), Some(4));
}

#[test]
fn test_parse_raw_btf_function_return_type_ids_big_endian() {
    let type_headers = [
        ((12u32 << 24) | 1, 2), // BTF_KIND_FUNC -> proto id 2
        (13u32 << 24, 0),       // BTF_KIND_FUNC_PROTO -> void return
    ];
    let raw = make_minimal_raw_btf_with_type_headers(BtfEndianness::Big, &type_headers);
    let parsed = parse_function_return_type_ids_from_raw_btf(&raw)
        .expect("expected return-type map from raw BTF");
    assert_eq!(parsed.get(&1).copied(), Some(0));
}

#[test]
fn test_lsm_hook_arg_type_info_file_open() {
    let arg = KernelBtf::get()
        .lsm_hook_arg_type_info("file_open", 0)
        .expect("expected file_open arg0 type info");
    assert!(arg.is_some(), "expected file_open arg0 to exist");
}
