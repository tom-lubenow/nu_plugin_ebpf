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
        function_arg_type_info_cache: RwLock::new(HashMap::new()),
        function_ret_type_info_cache: RwLock::new(HashMap::new()),
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
    assert!(matches!(
        field.type_info,
        TypeInfo::Ptr { is_user: false, .. }
    ));

    let field = service
        .parse_field_line("field:const char *filename;\toffset:24;\tsize:8;\tsigned:0;")
        .unwrap();
    assert_eq!(field.name, "filename");
    assert!(matches!(
        field.type_info,
        TypeInfo::Ptr { is_user: false, .. }
    ));

    let field = service
        .parse_field_line("field:const char __user *path;\toffset:24;\tsize:8;\tsigned:0;")
        .unwrap();
    assert_eq!(field.name, "path");
    assert!(matches!(
        field.type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

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
    assert_eq!(ctx.source, TracepointContextSource::TracefsFormat);
    assert_eq!(ctx.source_path, None);

    // Should have 5 non-common fields
    assert_eq!(ctx.fields.len(), 5);

    // Check specific fields
    let syscall_nr = ctx.get_field("__syscall_nr").unwrap();
    assert_eq!(syscall_nr.offset, 8);

    let filename = ctx.get_field("filename").unwrap();
    assert_eq!(filename.offset, 24);
    assert!(filename.type_info.is_ptr());
    assert!(matches!(
        filename.type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let other = service
        .parse_format_file(
            r#"name: demo
ID: 1
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:const char * name;       offset:8;       size:8; signed:0;
"#,
            "sched",
            "sched_process_exec",
        )
        .unwrap();
    assert!(matches!(
        other.get_field("name").unwrap().type_info,
        TypeInfo::Ptr { is_user: false, .. }
    ));
}

#[test]
fn test_wellknown_sys_enter() {
    let ctx = TracepointContext::sys_enter("sys_enter_openat");
    assert_eq!(ctx.category, "syscalls");
    assert_eq!(
        ctx.source,
        TracepointContextSource::WellKnownSyscallFallback
    );
    assert_eq!(ctx.source_path, None);
    assert_eq!(ctx.minimum_kernel(), Some("4.7"));
    assert!(
        ctx.minimum_kernel_source()
            .is_some_and(|source| source.contains("/v4.7/include/trace/events/syscalls.h"))
    );
    assert!(ctx.has_field("id"));
    assert!(ctx.has_field("args"));
    assert!(ctx.has_field("dfd"));
    assert!(ctx.has_field("filename"));
    assert!(ctx.has_field("flags"));
    assert!(ctx.has_field("mode"));

    let filename = ctx.get_field("filename").expect("expected filename field");
    assert_eq!(filename.offset, 24);
    assert!(matches!(
        filename.type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let flags = ctx.get_field("flags").expect("expected flags field");
    assert_eq!(flags.offset, 32);
    assert!(matches!(
        flags.type_info,
        TypeInfo::Int {
            size: 8,
            signed: false
        }
    ));
}

#[test]
fn test_wellknown_sys_enter_common_named_arg_fallbacks() {
    let read = TracepointContext::sys_enter("sys_enter_read");
    assert!(read.has_field("fd"));
    assert!(read.has_field("buf"));
    assert!(read.has_field("count"));
    assert!(matches!(
        read.get_field("buf").expect("expected read buf").type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let write = TracepointContext::sys_enter("sys_enter_write");
    assert!(write.has_field("fd"));
    assert!(write.has_field("buf"));
    assert!(write.has_field("count"));
    assert!(matches!(
        write
            .get_field("buf")
            .expect("expected write buf")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let pread64 = TracepointContext::sys_enter("sys_enter_pread64");
    assert!(pread64.has_field("fd"));
    assert!(pread64.has_field("buf"));
    assert!(pread64.has_field("count"));
    assert!(pread64.has_field("pos"));
    let (_, pread64_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_pread64",
        "buf",
    )
    .expect("expected pread64 buf source metadata");
    assert!(pread64_source.contains("/v4.7/fs/read_write.c"));
    assert!(matches!(
        pread64
            .get_field("buf")
            .expect("expected pread64 buf")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let readv = TracepointContext::sys_enter("sys_enter_readv");
    assert!(readv.has_field("fd"));
    assert!(readv.has_field("vec"));
    assert!(readv.has_field("vlen"));
    assert!(matches!(
        readv
            .get_field("vec")
            .expect("expected readv vec")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let preadv = TracepointContext::sys_enter("sys_enter_preadv");
    assert!(preadv.has_field("fd"));
    assert!(preadv.has_field("vec"));
    assert!(preadv.has_field("vlen"));
    assert!(preadv.has_field("pos_l"));
    assert!(preadv.has_field("pos_h"));

    let preadv2 = TracepointContext::sys_enter("sys_enter_preadv2");
    assert!(preadv2.has_field("fd"));
    assert!(preadv2.has_field("vec"));
    assert!(preadv2.has_field("vlen"));
    assert!(preadv2.has_field("pos_l"));
    assert!(preadv2.has_field("pos_h"));
    assert!(preadv2.has_field("flags"));
    assert!(matches!(
        preadv2
            .get_field("vec")
            .expect("expected preadv2 vec")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let sendfile = TracepointContext::sys_enter("sys_enter_sendfile");
    assert!(sendfile.has_field("out_fd"));
    assert!(sendfile.has_field("in_fd"));
    assert!(sendfile.has_field("offset"));
    assert!(sendfile.has_field("count"));
    let (_, sendfile_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_sendfile",
        "offset",
    )
    .expect("expected sendfile offset source metadata");
    assert!(sendfile_source.contains("/v4.7/fs/read_write.c"));
    assert!(matches!(
        sendfile
            .get_field("offset")
            .expect("expected sendfile offset")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let copy_file_range = TracepointContext::sys_enter("sys_enter_copy_file_range");
    assert!(copy_file_range.has_field("fd_in"));
    assert!(copy_file_range.has_field("off_in"));
    assert!(copy_file_range.has_field("fd_out"));
    assert!(copy_file_range.has_field("off_out"));
    assert!(copy_file_range.has_field("len"));
    assert!(copy_file_range.has_field("flags"));
    assert!(matches!(
        copy_file_range
            .get_field("off_out")
            .expect("expected copy_file_range off_out")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let splice = TracepointContext::sys_enter("sys_enter_splice");
    assert!(splice.has_field("fd_in"));
    assert!(splice.has_field("off_in"));
    assert!(splice.has_field("fd_out"));
    assert!(splice.has_field("off_out"));
    assert!(splice.has_field("len"));
    assert!(splice.has_field("flags"));
    let (_, splice_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_splice",
        "off_in",
    )
    .expect("expected splice off_in source metadata");
    assert!(splice_source.contains("/v4.7/fs/splice.c"));
    assert!(matches!(
        splice
            .get_field("off_in")
            .expect("expected splice off_in")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let tee = TracepointContext::sys_enter("sys_enter_tee");
    assert!(tee.has_field("fdin"));
    assert!(tee.has_field("fdout"));
    assert!(tee.has_field("len"));
    assert!(tee.has_field("flags"));

    let vmsplice = TracepointContext::sys_enter("sys_enter_vmsplice");
    assert!(vmsplice.has_field("fd"));
    assert!(vmsplice.has_field("iov"));
    assert!(vmsplice.has_field("nr_segs"));
    assert!(vmsplice.has_field("flags"));
    assert!(matches!(
        vmsplice
            .get_field("iov")
            .expect("expected vmsplice iov")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let close = TracepointContext::sys_enter("sys_enter_close");
    assert!(close.has_field("fd"));
    assert!(!close.has_field("buf"));

    let close_range = TracepointContext::sys_enter("sys_enter_close_range");
    assert!(close_range.has_field("fd"));
    assert!(close_range.has_field("max_fd"));
    assert!(close_range.has_field("flags"));
    assert_eq!(close_range.minimum_kernel(), Some("5.9"));
    assert!(
        close_range
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.9/fs/open.c"))
    );

    let openat2 = TracepointContext::sys_enter("sys_enter_openat2");
    assert!(openat2.has_field("dfd"));
    assert!(openat2.has_field("filename"));
    assert!(openat2.has_field("how"));
    assert!(openat2.has_field("usize"));
    assert!(!openat2.has_field("size"));
    assert_eq!(openat2.minimum_kernel(), Some("5.6"));
    assert!(
        openat2
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.6/fs/open.c"))
    );

    let faccessat2 = TracepointContext::sys_enter("sys_enter_faccessat2");
    assert!(faccessat2.has_field("dfd"));
    assert!(faccessat2.has_field("filename"));
    assert!(faccessat2.has_field("mode"));
    assert!(faccessat2.has_field("flags"));
    assert_eq!(faccessat2.minimum_kernel(), Some("5.8"));
    assert!(
        faccessat2
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.8/fs/open.c"))
    );
    assert!(matches!(
        faccessat2
            .get_field("filename")
            .expect("expected faccessat2 filename")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let fchmodat2 = TracepointContext::sys_enter("sys_enter_fchmodat2");
    assert!(fchmodat2.has_field("dfd"));
    assert!(fchmodat2.has_field("filename"));
    assert!(fchmodat2.has_field("mode"));
    assert!(fchmodat2.has_field("flags"));
    assert_eq!(fchmodat2.minimum_kernel(), Some("6.6"));
    assert!(
        fchmodat2
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v6.6/fs/open.c"))
    );
    let (_, fchmodat2_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_fchmodat2",
        "flags",
    )
    .expect("expected fchmodat2 flags source metadata");
    assert!(fchmodat2_source.contains("/v6.6/fs/open.c"));
    assert!(matches!(
        fchmodat2
            .get_field("filename")
            .expect("expected fchmodat2 filename")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let open = TracepointContext::sys_enter("sys_enter_open");
    assert!(open.has_field("filename"));
    assert!(open.has_field("flags"));
    assert!(open.has_field("mode"));
    assert!(matches!(
        open.get_field("filename")
            .expect("expected open filename")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, open_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_open",
        "filename",
    )
    .expect("expected open filename source metadata");
    assert!(open_source.contains("/v4.7/fs/open.c"));

    let fchownat = TracepointContext::sys_enter("sys_enter_fchownat");
    assert!(fchownat.has_field("dfd"));
    assert!(fchownat.has_field("filename"));
    assert!(fchownat.has_field("user"));
    assert!(fchownat.has_field("group"));
    assert!(fchownat.has_field("flag"));
    assert!(matches!(
        fchownat
            .get_field("filename")
            .expect("expected fchownat filename")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let mknod = TracepointContext::sys_enter("sys_enter_mknod");
    assert!(mknod.has_field("filename"));
    assert!(mknod.has_field("mode"));
    assert!(mknod.has_field("dev"));
    let (_, mknod_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_mknod",
        "filename",
    )
    .expect("expected mknod filename source metadata");
    assert!(mknod_source.contains("/v4.7/fs/namei.c"));

    let execve = TracepointContext::sys_enter("sys_enter_execve");
    assert!(execve.has_field("filename"));
    assert!(execve.has_field("argv"));
    assert!(execve.has_field("envp"));

    let execveat = TracepointContext::sys_enter("sys_enter_execveat");
    assert!(execveat.has_field("fd"));
    assert!(execveat.has_field("filename"));
    assert!(execveat.has_field("argv"));
    assert!(execveat.has_field("envp"));
    assert!(execveat.has_field("flags"));
    assert!(matches!(
        execveat
            .get_field("filename")
            .expect("expected execveat filename")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let wait4 = TracepointContext::sys_enter("sys_enter_wait4");
    assert!(wait4.has_field("upid"));
    assert!(wait4.has_field("stat_addr"));
    assert!(wait4.has_field("options"));
    assert!(wait4.has_field("ru"));
    assert!(matches!(
        wait4
            .get_field("stat_addr")
            .expect("expected wait4 stat_addr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let clone3 = TracepointContext::sys_enter("sys_enter_clone3");
    assert!(clone3.has_field("uargs"));
    assert!(clone3.has_field("size"));
    assert_eq!(clone3.minimum_kernel(), Some("5.3"));
    assert!(
        clone3
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.3/kernel/fork.c"))
    );
    assert!(matches!(
        clone3
            .get_field("uargs")
            .expect("expected clone3 uargs")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let io_uring_setup = TracepointContext::sys_enter("sys_enter_io_uring_setup");
    assert!(io_uring_setup.has_field("entries"));
    assert!(io_uring_setup.has_field("params"));
    assert_eq!(io_uring_setup.minimum_kernel(), Some("5.1"));
    assert!(
        io_uring_setup
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.1/fs/io_uring.c"))
    );
    assert!(matches!(
        io_uring_setup
            .get_field("params")
            .expect("expected io_uring_setup params")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let io_uring_enter = TracepointContext::sys_enter("sys_enter_io_uring_enter");
    assert!(io_uring_enter.has_field("fd"));
    assert!(io_uring_enter.has_field("to_submit"));
    assert!(io_uring_enter.has_field("min_complete"));
    assert!(io_uring_enter.has_field("flags"));
    assert!(io_uring_enter.has_field("sig"));
    assert!(io_uring_enter.has_field("sigsz"));
    assert!(matches!(
        io_uring_enter
            .get_field("sig")
            .expect("expected io_uring_enter sig")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let io_uring_register = TracepointContext::sys_enter("sys_enter_io_uring_register");
    assert!(io_uring_register.has_field("fd"));
    assert!(io_uring_register.has_field("opcode"));
    assert!(!io_uring_register.has_field("arg"));
    assert!(io_uring_register.has_field("nr_args"));
    assert_eq!(io_uring_register.minimum_kernel(), Some("5.1"));
    assert!(
        io_uring_register
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.1/fs/io_uring.c"))
    );
    assert_eq!(
        io_uring_register
            .get_field("nr_args")
            .expect("expected io_uring_register nr_args")
            .offset,
        40
    );

    let io_pgetevents = TracepointContext::sys_enter("sys_enter_io_pgetevents");
    assert!(io_pgetevents.has_field("ctx_id"));
    assert!(io_pgetevents.has_field("min_nr"));
    assert!(io_pgetevents.has_field("nr"));
    assert!(io_pgetevents.has_field("events"));
    assert!(io_pgetevents.has_field("timeout"));
    assert!(io_pgetevents.has_field("usig"));
    assert_eq!(io_pgetevents.minimum_kernel(), Some("4.18"));
    assert!(
        io_pgetevents
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v4.18/fs/aio.c"))
    );
    assert!(matches!(
        io_pgetevents
            .get_field("usig")
            .expect("expected io_pgetevents usig")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, io_pgetevents_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_io_pgetevents",
        "events",
    )
    .expect("expected io_pgetevents source metadata");
    assert!(io_pgetevents_source.contains("/v4.18/fs/aio.c"));

    let mbind = TracepointContext::sys_enter("sys_enter_mbind");
    assert!(mbind.has_field("start"));
    assert!(mbind.has_field("len"));
    assert!(mbind.has_field("mode"));
    assert!(mbind.has_field("nmask"));
    assert!(mbind.has_field("maxnode"));
    assert!(mbind.has_field("flags"));
    assert!(matches!(
        mbind
            .get_field("nmask")
            .expect("expected mbind nmask")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, mbind_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_mbind",
        "nmask",
    )
    .expect("expected mbind source metadata");
    assert!(mbind_source.contains("/v4.7/mm/mempolicy.c"));

    let move_pages = TracepointContext::sys_enter("sys_enter_move_pages");
    assert!(!move_pages.has_field("pid"));
    assert!(move_pages.has_field("nr_pages"));
    assert!(move_pages.has_field("pages"));
    assert!(move_pages.has_field("nodes"));
    assert!(move_pages.has_field("status"));
    assert!(move_pages.has_field("flags"));
    assert_eq!(
        move_pages
            .get_field("nr_pages")
            .expect("expected move_pages nr_pages")
            .offset,
        24
    );
    let (_, move_pages_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_move_pages",
        "pages",
    )
    .expect("expected move_pages source metadata");
    assert!(move_pages_source.contains("/v4.7/mm/migrate.c"));

    let set_mempolicy_home_node = TracepointContext::sys_enter("sys_enter_set_mempolicy_home_node");
    assert!(set_mempolicy_home_node.has_field("start"));
    assert!(set_mempolicy_home_node.has_field("len"));
    assert!(set_mempolicy_home_node.has_field("home_node"));
    assert!(set_mempolicy_home_node.has_field("flags"));
    assert_eq!(set_mempolicy_home_node.minimum_kernel(), Some("5.17"));
    assert!(
        set_mempolicy_home_node
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.17/mm/mempolicy.c"))
    );

    let add_key = TracepointContext::sys_enter("sys_enter_add_key");
    assert!(add_key.has_field("_type"));
    assert!(add_key.has_field("_description"));
    assert!(add_key.has_field("_payload"));
    assert!(add_key.has_field("plen"));
    assert!(add_key.has_field("ringid"));
    assert!(matches!(
        add_key
            .get_field("_payload")
            .expect("expected add_key _payload")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, add_key_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_add_key",
        "_payload",
    )
    .expect("expected add_key source metadata");
    assert!(add_key_source.contains("/v4.7/security/keys/keyctl.c"));

    let keyctl = TracepointContext::sys_enter("sys_enter_keyctl");
    assert!(keyctl.has_field("option"));
    assert!(!keyctl.has_field("arg2"));
    let (_, keyctl_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_keyctl",
        "option",
    )
    .expect("expected keyctl source metadata");
    assert!(keyctl_source.contains("/v4.7/security/keys/keyctl.c"));

    let mq_open = TracepointContext::sys_enter("sys_enter_mq_open");
    assert!(mq_open.has_field("u_name"));
    assert!(mq_open.has_field("oflag"));
    assert!(mq_open.has_field("mode"));
    assert!(mq_open.has_field("u_attr"));
    assert!(matches!(
        mq_open
            .get_field("u_name")
            .expect("expected mq_open u_name")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, mq_open_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_mq_open",
        "u_attr",
    )
    .expect("expected mq_open source metadata");
    assert!(mq_open_source.contains("/v4.7/ipc/mqueue.c"));

    let mq_timedreceive = TracepointContext::sys_enter("sys_enter_mq_timedreceive");
    assert!(mq_timedreceive.has_field("mqdes"));
    assert!(mq_timedreceive.has_field("u_msg_ptr"));
    assert!(mq_timedreceive.has_field("msg_len"));
    assert!(mq_timedreceive.has_field("u_msg_prio"));
    assert!(mq_timedreceive.has_field("u_abs_timeout"));
    assert_eq!(
        mq_timedreceive
            .get_field("u_abs_timeout")
            .expect("expected mq_timedreceive u_abs_timeout")
            .offset,
        48
    );

    let epoll_ctl = TracepointContext::sys_enter("sys_enter_epoll_ctl");
    assert!(epoll_ctl.has_field("epfd"));
    assert!(epoll_ctl.has_field("op"));
    assert!(epoll_ctl.has_field("fd"));
    assert!(epoll_ctl.has_field("event"));
    assert!(matches!(
        epoll_ctl
            .get_field("event")
            .expect("expected epoll_ctl event")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let newfstatat = TracepointContext::sys_enter("sys_enter_newfstatat");
    assert!(newfstatat.has_field("dfd"));
    assert!(newfstatat.has_field("filename"));
    assert!(newfstatat.has_field("statbuf"));
    assert!(newfstatat.has_field("flag"));
    assert!(matches!(
        newfstatat
            .get_field("statbuf")
            .expect("expected newfstatat statbuf")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let statx = TracepointContext::sys_enter("sys_enter_statx");
    assert!(statx.has_field("dfd"));
    assert!(statx.has_field("filename"));
    assert!(statx.has_field("flags"));
    assert!(statx.has_field("mask"));
    assert!(statx.has_field("buffer"));
    assert_eq!(statx.minimum_kernel(), Some("4.11"));
    assert!(
        statx
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v4.11/fs/stat.c"))
    );
    assert!(matches!(
        statx
            .get_field("buffer")
            .expect("expected statx buffer")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let setxattr = TracepointContext::sys_enter("sys_enter_setxattr");
    assert!(setxattr.has_field("pathname"));
    assert!(setxattr.has_field("name"));
    assert!(setxattr.has_field("value"));
    assert!(setxattr.has_field("size"));
    assert!(setxattr.has_field("flags"));
    let (_, setxattr_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_setxattr",
        "value",
    )
    .expect("expected setxattr value source metadata");
    assert!(setxattr_source.contains("/v4.7/fs/xattr.c"));
    assert!(matches!(
        setxattr
            .get_field("value")
            .expect("expected setxattr value")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let fgetxattr = TracepointContext::sys_enter("sys_enter_fgetxattr");
    assert!(fgetxattr.has_field("fd"));
    assert!(fgetxattr.has_field("name"));
    assert!(fgetxattr.has_field("value"));
    assert!(fgetxattr.has_field("size"));

    let listxattr = TracepointContext::sys_enter("sys_enter_listxattr");
    assert!(listxattr.has_field("pathname"));
    assert!(listxattr.has_field("list"));
    assert!(listxattr.has_field("size"));

    let fremovexattr = TracepointContext::sys_enter("sys_enter_fremovexattr");
    assert!(fremovexattr.has_field("fd"));
    assert!(fremovexattr.has_field("name"));
    assert!(matches!(
        fremovexattr
            .get_field("name")
            .expect("expected fremovexattr name")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let setxattrat = TracepointContext::sys_enter("sys_enter_setxattrat");
    assert!(setxattrat.has_field("dfd"));
    assert!(setxattrat.has_field("pathname"));
    assert!(setxattrat.has_field("at_flags"));
    assert!(setxattrat.has_field("name"));
    assert!(setxattrat.has_field("uargs"));
    assert!(setxattrat.has_field("usize"));
    assert_eq!(setxattrat.minimum_kernel(), Some("6.13"));
    assert!(
        setxattrat
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v6.13/fs/xattr.c"))
    );
    let (_, setxattrat_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_setxattrat",
        "uargs",
    )
    .expect("expected setxattrat uargs source metadata");
    assert!(setxattrat_source.contains("/v6.13/fs/xattr.c"));
    assert!(matches!(
        setxattrat
            .get_field("uargs")
            .expect("expected setxattrat uargs")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let listxattrat = TracepointContext::sys_enter("sys_enter_listxattrat");
    assert!(listxattrat.has_field("dfd"));
    assert!(listxattrat.has_field("pathname"));
    assert!(listxattrat.has_field("at_flags"));
    assert!(listxattrat.has_field("list"));
    assert!(listxattrat.has_field("size"));

    let removexattrat = TracepointContext::sys_enter("sys_enter_removexattrat");
    assert!(removexattrat.has_field("dfd"));
    assert!(removexattrat.has_field("pathname"));
    assert!(removexattrat.has_field("at_flags"));
    assert!(removexattrat.has_field("name"));

    let open_tree = TracepointContext::sys_enter("sys_enter_open_tree");
    assert!(open_tree.has_field("dfd"));
    assert!(open_tree.has_field("filename"));
    assert!(open_tree.has_field("flags"));
    assert_eq!(open_tree.minimum_kernel(), Some("5.2"));
    assert!(
        open_tree
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.2/fs/namespace.c"))
    );
    assert!(matches!(
        open_tree
            .get_field("filename")
            .expect("expected open_tree filename")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let fsconfig = TracepointContext::sys_enter("sys_enter_fsconfig");
    assert!(fsconfig.has_field("fd"));
    assert!(fsconfig.has_field("cmd"));
    assert!(fsconfig.has_field("_key"));
    assert!(fsconfig.has_field("_value"));
    assert!(fsconfig.has_field("aux"));
    assert_eq!(fsconfig.minimum_kernel(), Some("5.2"));
    assert!(
        fsconfig
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.2/fs/fsopen.c"))
    );
    assert!(matches!(
        fsconfig
            .get_field("_value")
            .expect("expected fsconfig _value")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let mount_setattr = TracepointContext::sys_enter("sys_enter_mount_setattr");
    assert!(mount_setattr.has_field("dfd"));
    assert!(mount_setattr.has_field("path"));
    assert!(mount_setattr.has_field("flags"));
    assert!(mount_setattr.has_field("uattr"));
    assert!(mount_setattr.has_field("usize"));
    assert_eq!(mount_setattr.minimum_kernel(), Some("5.12"));
    assert!(
        mount_setattr
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.12/fs/namespace.c"))
    );
    assert_eq!(
        mount_setattr
            .get_field("usize")
            .expect("expected mount_setattr usize")
            .offset,
        48
    );

    let memfd_create = TracepointContext::sys_enter("sys_enter_memfd_create");
    assert!(memfd_create.has_field("uname"));
    assert!(memfd_create.has_field("flags"));
    let (_, memfd_create_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_memfd_create",
        "uname",
    )
    .expect("expected memfd_create uname source metadata");
    assert!(memfd_create_source.contains("/v4.7/mm/shmem.c"));
    assert!(matches!(
        memfd_create
            .get_field("uname")
            .expect("expected memfd_create uname")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let memfd_secret = TracepointContext::sys_enter("sys_enter_memfd_secret");
    assert!(memfd_secret.has_field("flags"));
    assert_eq!(memfd_secret.minimum_kernel(), Some("5.14"));
    assert!(
        memfd_secret
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.14/mm/secretmem.c"))
    );

    let process_madvise = TracepointContext::sys_enter("sys_enter_process_madvise");
    assert!(process_madvise.has_field("pidfd"));
    assert!(process_madvise.has_field("vec"));
    assert!(process_madvise.has_field("vlen"));
    assert!(process_madvise.has_field("behavior"));
    assert!(process_madvise.has_field("flags"));
    assert_eq!(process_madvise.minimum_kernel(), Some("5.10"));
    assert!(
        process_madvise
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.10/mm/madvise.c"))
    );
    assert!(matches!(
        process_madvise
            .get_field("vec")
            .expect("expected process_madvise vec")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    assert_eq!(
        process_madvise
            .get_field("flags")
            .expect("expected process_madvise flags")
            .offset,
        48
    );

    let process_mrelease = TracepointContext::sys_enter("sys_enter_process_mrelease");
    assert!(process_mrelease.has_field("pidfd"));
    assert!(process_mrelease.has_field("flags"));
    assert_eq!(process_mrelease.minimum_kernel(), Some("5.15"));
    assert!(
        process_mrelease
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.15/mm/oom_kill.c"))
    );

    let pidfd_send_signal = TracepointContext::sys_enter("sys_enter_pidfd_send_signal");
    assert!(pidfd_send_signal.has_field("pidfd"));
    assert!(pidfd_send_signal.has_field("sig"));
    assert!(pidfd_send_signal.has_field("info"));
    assert!(pidfd_send_signal.has_field("flags"));
    assert_eq!(pidfd_send_signal.minimum_kernel(), Some("5.1"));
    assert!(
        pidfd_send_signal
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.1/kernel/signal.c"))
    );
    assert!(matches!(
        pidfd_send_signal
            .get_field("info")
            .expect("expected pidfd_send_signal info")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let pidfd_open = TracepointContext::sys_enter("sys_enter_pidfd_open");
    assert!(!pidfd_open.has_field("pid"));
    assert!(pidfd_open.has_field("flags"));
    assert_eq!(pidfd_open.minimum_kernel(), Some("5.3"));
    assert!(
        pidfd_open
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.3/kernel/pid.c"))
    );

    let pidfd_getfd = TracepointContext::sys_enter("sys_enter_pidfd_getfd");
    assert!(pidfd_getfd.has_field("pidfd"));
    assert!(pidfd_getfd.has_field("fd"));
    assert!(pidfd_getfd.has_field("flags"));
    assert_eq!(pidfd_getfd.minimum_kernel(), Some("5.6"));
    assert!(
        pidfd_getfd
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.6/kernel/pid.c"))
    );

    let landlock_create_ruleset = TracepointContext::sys_enter("sys_enter_landlock_create_ruleset");
    assert!(landlock_create_ruleset.has_field("attr"));
    assert!(landlock_create_ruleset.has_field("size"));
    assert!(landlock_create_ruleset.has_field("flags"));
    assert_eq!(landlock_create_ruleset.minimum_kernel(), Some("5.13"));
    assert!(
        landlock_create_ruleset
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.13/security/landlock/syscalls.c"))
    );
    assert!(matches!(
        landlock_create_ruleset
            .get_field("attr")
            .expect("expected landlock_create_ruleset attr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let landlock_add_rule = TracepointContext::sys_enter("sys_enter_landlock_add_rule");
    assert!(landlock_add_rule.has_field("ruleset_fd"));
    assert!(landlock_add_rule.has_field("rule_type"));
    assert!(landlock_add_rule.has_field("rule_attr"));
    assert!(landlock_add_rule.has_field("flags"));
    assert!(matches!(
        landlock_add_rule
            .get_field("rule_attr")
            .expect("expected landlock_add_rule rule_attr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let old_mmap = TracepointContext::sys_enter("sys_enter_old_mmap");
    assert!(old_mmap.has_field("id"));
    assert!(old_mmap.has_field("args"));
    assert!(
        !old_mmap.has_field("arg"),
        "sys_enter_old_mmap's kernel argument name collides with ctx.arg.<name>"
    );

    let setresuid = TracepointContext::sys_enter("sys_enter_setresuid");
    assert!(setresuid.has_field("ruid"));
    assert!(setresuid.has_field("euid"));
    assert!(setresuid.has_field("suid"));
    let (_, setresuid_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_setresuid",
        "euid",
    )
    .expect("expected setresuid euid source metadata");
    assert!(setresuid_source.contains("/v4.7/kernel/sys.c"));

    let capset = TracepointContext::sys_enter("sys_enter_capset");
    assert!(capset.has_field("header"));
    assert!(capset.has_field("data"));
    assert!(matches!(
        capset
            .get_field("data")
            .expect("expected capset data")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, capset_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_capset",
        "data",
    )
    .expect("expected capset data source metadata");
    assert!(capset_source.contains("/v4.7/kernel/capability.c"));

    let connect = TracepointContext::sys_enter("sys_enter_connect");
    assert!(connect.has_field("fd"));
    assert!(connect.has_field("uservaddr"));
    assert!(connect.has_field("addrlen"));
    assert!(matches!(
        connect
            .get_field("uservaddr")
            .expect("expected connect uservaddr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let sendto = TracepointContext::sys_enter("sys_enter_sendto");
    assert!(sendto.has_field("fd"));
    assert!(sendto.has_field("buff"));
    assert!(sendto.has_field("len"));
    assert!(sendto.has_field("flags"));
    assert!(sendto.has_field("addr"));
    assert!(sendto.has_field("addr_len"));
    assert!(matches!(
        sendto
            .get_field("addr")
            .expect("expected sendto addr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let recvfrom = TracepointContext::sys_enter("sys_enter_recvfrom");
    assert!(recvfrom.has_field("fd"));
    assert!(recvfrom.has_field("ubuf"));
    assert!(recvfrom.has_field("size"));
    assert!(recvfrom.has_field("flags"));
    assert!(recvfrom.has_field("addr"));
    assert!(recvfrom.has_field("addr_len"));
    assert!(matches!(
        recvfrom
            .get_field("addr_len")
            .expect("expected recvfrom addr_len")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let accept4 = TracepointContext::sys_enter("sys_enter_accept4");
    assert!(accept4.has_field("fd"));
    assert!(accept4.has_field("upeer_sockaddr"));
    assert!(accept4.has_field("upeer_addrlen"));
    assert!(accept4.has_field("flags"));
    assert!(matches!(
        accept4
            .get_field("upeer_sockaddr")
            .expect("expected accept4 upeer_sockaddr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let utimensat = TracepointContext::sys_enter("sys_enter_utimensat");
    assert!(utimensat.has_field("dfd"));
    assert!(utimensat.has_field("filename"));
    assert!(utimensat.has_field("utimes"));
    assert!(utimensat.has_field("flags"));
    assert!(matches!(
        utimensat
            .get_field("filename")
            .expect("expected utimensat filename")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, utimensat_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_utimensat",
        "utimes",
    )
    .expect("expected utimensat source metadata");
    assert!(utimensat_source.contains("/v4.7/fs/utimes.c"));

    let ppoll = TracepointContext::sys_enter("sys_enter_ppoll");
    assert!(ppoll.has_field("ufds"));
    assert!(ppoll.has_field("nfds"));
    assert!(ppoll.has_field("tsp"));
    assert!(ppoll.has_field("sigmask"));
    assert!(ppoll.has_field("sigsetsize"));
    assert!(matches!(
        ppoll
            .get_field("ufds")
            .expect("expected ppoll ufds")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, ppoll_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_ppoll",
        "sigmask",
    )
    .expect("expected ppoll source metadata");
    assert!(ppoll_source.contains("/v4.7/fs/select.c"));

    let epoll_pwait2 = TracepointContext::sys_enter("sys_enter_epoll_pwait2");
    assert!(epoll_pwait2.has_field("epfd"));
    assert!(epoll_pwait2.has_field("events"));
    assert!(epoll_pwait2.has_field("maxevents"));
    assert!(epoll_pwait2.has_field("timeout"));
    assert!(epoll_pwait2.has_field("sigmask"));
    assert!(epoll_pwait2.has_field("sigsetsize"));
    assert_eq!(epoll_pwait2.minimum_kernel(), Some("5.11"));
    assert!(
        epoll_pwait2
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.11/fs/eventpoll.c"))
    );

    let sync_file_range = TracepointContext::sys_enter("sys_enter_sync_file_range");
    assert!(sync_file_range.has_field("fd"));
    assert!(sync_file_range.has_field("offset"));
    assert!(sync_file_range.has_field("nbytes"));
    assert!(sync_file_range.has_field("flags"));
    let (_, sync_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_sync_file_range",
        "nbytes",
    )
    .expect("expected sync_file_range source metadata");
    assert!(sync_source.contains("/v4.7/fs/sync.c"));

    let ioctl = TracepointContext::sys_enter("sys_enter_ioctl");
    assert!(ioctl.has_field("fd"));
    assert!(ioctl.has_field("cmd"));
    let (_, ioctl_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_ioctl",
        "cmd",
    )
    .expect("expected ioctl source metadata");
    assert!(ioctl_source.contains("/v4.7/fs/ioctl.c"));

    let readlinkat = TracepointContext::sys_enter("sys_enter_readlinkat");
    assert!(readlinkat.has_field("dfd"));
    assert!(readlinkat.has_field("pathname"));
    assert!(readlinkat.has_field("buf"));
    assert!(readlinkat.has_field("bufsiz"));
    assert!(matches!(
        readlinkat
            .get_field("pathname")
            .expect("expected readlinkat pathname")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, readlinkat_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_readlinkat",
        "pathname",
    )
    .expect("expected readlinkat source metadata");
    assert!(readlinkat_source.contains("/v4.7/fs/stat.c"));

    let name_to_handle_at = TracepointContext::sys_enter("sys_enter_name_to_handle_at");
    assert!(name_to_handle_at.has_field("dfd"));
    assert!(name_to_handle_at.has_field("name"));
    assert!(name_to_handle_at.has_field("handle"));
    assert!(name_to_handle_at.has_field("mnt_id"));
    assert!(name_to_handle_at.has_field("flag"));
    let (_, handle_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_name_to_handle_at",
        "handle",
    )
    .expect("expected name_to_handle_at source metadata");
    assert!(handle_source.contains("/v4.7/fs/fhandle.c"));

    let fanotify_mark = TracepointContext::sys_enter("sys_enter_fanotify_mark");
    assert!(fanotify_mark.has_field("fanotify_fd"));
    assert!(fanotify_mark.has_field("flags"));
    assert!(fanotify_mark.has_field("mask"));
    assert!(fanotify_mark.has_field("dfd"));
    assert!(fanotify_mark.has_field("pathname"));
    assert!(matches!(
        fanotify_mark
            .get_field("pathname")
            .expect("expected fanotify_mark pathname")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, fanotify_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_fanotify_mark",
        "pathname",
    )
    .expect("expected fanotify_mark source metadata");
    assert!(fanotify_source.contains("/v4.7/fs/notify/fanotify/fanotify_user.c"));

    let getpeername = TracepointContext::sys_enter("sys_enter_getpeername");
    assert!(getpeername.has_field("fd"));
    assert!(getpeername.has_field("usockaddr"));
    assert!(getpeername.has_field("usockaddr_len"));
    assert!(matches!(
        getpeername
            .get_field("usockaddr")
            .expect("expected getpeername usockaddr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, getpeername_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_getpeername",
        "usockaddr",
    )
    .expect("expected getpeername source metadata");
    assert!(getpeername_source.contains("/v4.7/net/socket.c"));

    let signalfd4 = TracepointContext::sys_enter("sys_enter_signalfd4");
    assert!(signalfd4.has_field("ufd"));
    assert!(signalfd4.has_field("user_mask"));
    assert!(signalfd4.has_field("sizemask"));
    assert!(signalfd4.has_field("flags"));
    let (_, signalfd_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_signalfd4",
        "user_mask",
    )
    .expect("expected signalfd4 source metadata");
    assert!(signalfd_source.contains("/v4.7/fs/signalfd.c"));

    let getrandom = TracepointContext::sys_enter("sys_enter_getrandom");
    assert!(getrandom.has_field("buf"));
    assert!(getrandom.has_field("count"));
    assert!(getrandom.has_field("flags"));
    let (_, getrandom_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_getrandom",
        "buf",
    )
    .expect("expected getrandom source metadata");
    assert!(getrandom_source.contains("/v4.7/drivers/char/random.c"));

    let futex = TracepointContext::sys_enter("sys_enter_futex");
    assert!(futex.has_field("uaddr"));
    assert!(futex.has_field("op"));
    assert!(futex.has_field("val"));
    assert!(futex.has_field("utime"));
    assert!(futex.has_field("uaddr2"));
    assert!(futex.has_field("val3"));
    assert!(matches!(
        futex
            .get_field("uaddr")
            .expect("expected futex uaddr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    assert!(matches!(
        futex
            .get_field("utime")
            .expect("expected futex utime")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, futex_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_futex",
        "uaddr",
    )
    .expect("expected futex uaddr source metadata");
    assert!(futex_source.contains("/v4.7/kernel/futex.c"));

    for (name, fields) in [
        ("sys_enter_open", &["filename", "flags", "mode"][..]),
        ("sys_enter_creat", &["pathname", "mode"][..]),
        ("sys_enter_access", &["filename", "mode"][..]),
        ("sys_enter_faccessat", &["dfd", "filename", "mode"][..]),
        (
            "sys_enter_faccessat2",
            &["dfd", "filename", "mode", "flags"][..],
        ),
        ("sys_enter_truncate", &["path", "length"][..]),
        ("sys_enter_truncate64", &["path", "length"][..]),
        ("sys_enter_ftruncate", &["fd", "length"][..]),
        ("sys_enter_ftruncate64", &["fd", "length"][..]),
        ("sys_enter_chmod", &["filename", "mode"][..]),
        ("sys_enter_fchmod", &["fd", "mode"][..]),
        ("sys_enter_fchmodat", &["dfd", "filename", "mode"][..]),
        (
            "sys_enter_fchmodat2",
            &["dfd", "filename", "mode", "flags"][..],
        ),
        ("sys_enter_chown", &["filename", "user", "group"][..]),
        ("sys_enter_lchown", &["filename", "user", "group"][..]),
        ("sys_enter_fchown", &["fd", "user", "group"][..]),
        (
            "sys_enter_fchownat",
            &["dfd", "filename", "user", "group", "flag"][..],
        ),
        ("sys_enter_socket", &["family", "type", "protocol"][..]),
        (
            "sys_enter_socketpair",
            &["family", "type", "protocol", "usockvec"][..],
        ),
        ("sys_enter_bind", &["fd", "umyaddr", "addrlen"][..]),
        ("sys_enter_listen", &["fd", "backlog"][..]),
        (
            "sys_enter_accept",
            &["fd", "upeer_sockaddr", "upeer_addrlen"][..],
        ),
        (
            "sys_enter_setsockopt",
            &["fd", "level", "optname", "optval", "optlen"][..],
        ),
        (
            "sys_enter_getsockopt",
            &["fd", "level", "optname", "optval", "optlen"][..],
        ),
        (
            "sys_enter_getsockname",
            &["fd", "usockaddr", "usockaddr_len"][..],
        ),
        (
            "sys_enter_getpeername",
            &["fd", "usockaddr", "usockaddr_len"][..],
        ),
        ("sys_enter_shutdown", &["fd", "how"][..]),
        ("sys_enter_sendmsg", &["fd", "msg", "flags"][..]),
        ("sys_enter_recvmsg", &["fd", "msg", "flags"][..]),
        ("sys_enter_sendmmsg", &["fd", "mmsg", "vlen", "flags"][..]),
        (
            "sys_enter_recvmmsg",
            &["fd", "mmsg", "vlen", "flags", "timeout"][..],
        ),
        ("sys_enter_exit", &["error_code"][..]),
        ("sys_enter_exit_group", &["error_code"][..]),
        (
            "sys_enter_waitid",
            &["which", "upid", "infop", "options", "ru"][..],
        ),
        ("sys_enter_unshare", &["unshare_flags"][..]),
        ("sys_enter_clone3", &["uargs", "size"][..]),
        ("sys_enter_setns", &["fd", "nstype"][..]),
        ("sys_enter_dup", &["fildes"][..]),
        ("sys_enter_dup2", &["oldfd", "newfd"][..]),
        ("sys_enter_dup3", &["oldfd", "newfd", "flags"][..]),
        ("sys_enter_pipe", &["fildes"][..]),
        ("sys_enter_pipe2", &["fildes", "flags"][..]),
        ("sys_enter_eventfd", &["count"][..]),
        ("sys_enter_eventfd2", &["count", "flags"][..]),
        ("sys_enter_close_range", &["fd", "max_fd", "flags"][..]),
        ("sys_enter_epoll_create", &["size"][..]),
        ("sys_enter_epoll_create1", &["flags"][..]),
        (
            "sys_enter_epoll_wait",
            &["epfd", "events", "maxevents", "timeout"][..],
        ),
        (
            "sys_enter_epoll_pwait",
            &[
                "epfd",
                "events",
                "maxevents",
                "timeout",
                "sigmask",
                "sigsetsize",
            ][..],
        ),
        (
            "sys_enter_epoll_pwait2",
            &[
                "epfd",
                "events",
                "maxevents",
                "timeout",
                "sigmask",
                "sigsetsize",
            ][..],
        ),
        ("sys_enter_inotify_init", &[][..]),
        ("sys_enter_inotify_init1", &["flags"][..]),
        (
            "sys_enter_inotify_add_watch",
            &["fd", "pathname", "mask"][..],
        ),
        ("sys_enter_inotify_rm_watch", &["fd", "wd"][..]),
        ("sys_enter_fanotify_init", &["flags", "event_f_flags"][..]),
        (
            "sys_enter_fanotify_mark",
            &["fanotify_fd", "flags", "mask", "dfd", "pathname"][..],
        ),
        ("sys_enter_poll", &["ufds", "nfds", "timeout_msecs"][..]),
        (
            "sys_enter_ppoll",
            &["ufds", "nfds", "tsp", "sigmask", "sigsetsize"][..],
        ),
        ("sys_enter_select", &["n", "inp", "outp", "exp", "tvp"][..]),
        (
            "sys_enter_pselect6",
            &["n", "inp", "outp", "exp", "tsp", "sig"][..],
        ),
        ("sys_enter_lseek", &["fd", "offset", "whence"][..]),
        (
            "sys_enter_fadvise64",
            &["fd", "offset", "len", "advice"][..],
        ),
        ("sys_enter_readahead", &["fd", "offset", "count"][..]),
        ("sys_enter_fallocate", &["fd", "mode", "offset", "len"][..]),
        ("sys_enter_sync", &[][..]),
        ("sys_enter_syncfs", &["fd"][..]),
        ("sys_enter_fsync", &["fd"][..]),
        ("sys_enter_fdatasync", &["fd"][..]),
        (
            "sys_enter_sync_file_range",
            &["fd", "offset", "nbytes", "flags"][..],
        ),
        ("sys_enter_fcntl", &["fd", "cmd"][..]),
        ("sys_enter_flock", &["fd", "cmd"][..]),
        ("sys_enter_ioctl", &["fd", "cmd"][..]),
        ("sys_enter_chdir", &["filename"][..]),
        ("sys_enter_fchdir", &["fd"][..]),
        ("sys_enter_chroot", &["filename"][..]),
        ("sys_enter_getcwd", &["buf", "size"][..]),
        ("sys_enter_readlink", &["path", "buf", "bufsiz"][..]),
        (
            "sys_enter_readlinkat",
            &["dfd", "pathname", "buf", "bufsiz"][..],
        ),
        ("sys_enter_statfs", &["pathname", "buf"][..]),
        ("sys_enter_fstatfs", &["fd", "buf"][..]),
        ("sys_enter_getdents", &["fd", "dirent", "count"][..]),
        ("sys_enter_getdents64", &["fd", "dirent", "count"][..]),
        (
            "sys_enter_name_to_handle_at",
            &["dfd", "name", "handle", "mnt_id", "flag"][..],
        ),
        (
            "sys_enter_open_by_handle_at",
            &["mountdirfd", "handle", "flags"][..],
        ),
        ("sys_enter_stat", &["filename", "statbuf"][..]),
        ("sys_enter_newstat", &["filename", "statbuf"][..]),
        ("sys_enter_fstat", &["fd", "statbuf"][..]),
        ("sys_enter_newfstat", &["fd", "statbuf"][..]),
        ("sys_enter_mknod", &["filename", "mode", "dev"][..]),
        ("sys_enter_mknodat", &["dfd", "filename", "mode", "dev"][..]),
        ("sys_enter_mkdir", &["pathname", "mode"][..]),
        ("sys_enter_mkdirat", &["dfd", "pathname", "mode"][..]),
        ("sys_enter_rmdir", &["pathname"][..]),
        ("sys_enter_unlink", &["pathname"][..]),
        ("sys_enter_unlinkat", &["dfd", "pathname", "flag"][..]),
        ("sys_enter_symlink", &["oldname", "newname"][..]),
        ("sys_enter_symlinkat", &["oldname", "newdfd", "newname"][..]),
        ("sys_enter_link", &["oldname", "newname"][..]),
        (
            "sys_enter_linkat",
            &["olddfd", "oldname", "newdfd", "newname", "flags"][..],
        ),
        ("sys_enter_rename", &["oldname", "newname"][..]),
        (
            "sys_enter_renameat",
            &["olddfd", "oldname", "newdfd", "newname"][..],
        ),
        (
            "sys_enter_renameat2",
            &["olddfd", "oldname", "newdfd", "newname", "flags"][..],
        ),
        (
            "sys_enter_setxattr",
            &["pathname", "name", "value", "size", "flags"][..],
        ),
        (
            "sys_enter_fsetxattr",
            &["fd", "name", "value", "size", "flags"][..],
        ),
        (
            "sys_enter_getxattr",
            &["pathname", "name", "value", "size"][..],
        ),
        ("sys_enter_fgetxattr", &["fd", "name", "value", "size"][..]),
        ("sys_enter_listxattr", &["pathname", "list", "size"][..]),
        ("sys_enter_flistxattr", &["fd", "list", "size"][..]),
        ("sys_enter_removexattr", &["pathname", "name"][..]),
        ("sys_enter_fremovexattr", &["fd", "name"][..]),
        (
            "sys_enter_setxattrat",
            &["dfd", "pathname", "at_flags", "name", "uargs", "usize"][..],
        ),
        (
            "sys_enter_getxattrat",
            &["dfd", "pathname", "at_flags", "name", "uargs", "usize"][..],
        ),
        (
            "sys_enter_listxattrat",
            &["dfd", "pathname", "at_flags", "list", "size"][..],
        ),
        (
            "sys_enter_removexattrat",
            &["dfd", "pathname", "at_flags", "name"][..],
        ),
        ("sys_enter_open_tree", &["dfd", "filename", "flags"][..]),
        (
            "sys_enter_move_mount",
            &[
                "from_dfd",
                "from_pathname",
                "to_dfd",
                "to_pathname",
                "flags",
            ][..],
        ),
        ("sys_enter_fsopen", &["_fs_name", "flags"][..]),
        (
            "sys_enter_fsconfig",
            &["fd", "cmd", "_key", "_value", "aux"][..],
        ),
        ("sys_enter_fsmount", &["fs_fd", "flags", "attr_flags"][..]),
        ("sys_enter_fspick", &["dfd", "path", "flags"][..]),
        (
            "sys_enter_mount_setattr",
            &["dfd", "path", "flags", "uattr", "usize"][..],
        ),
        (
            "sys_enter_process_madvise",
            &["pidfd", "vec", "vlen", "behavior", "flags"][..],
        ),
        ("sys_enter_process_mrelease", &["pidfd", "flags"][..]),
        (
            "sys_enter_mbind",
            &["start", "len", "mode", "nmask", "maxnode", "flags"][..],
        ),
        ("sys_enter_set_mempolicy", &["mode", "nmask", "maxnode"][..]),
        (
            "sys_enter_get_mempolicy",
            &["policy", "nmask", "maxnode", "addr", "flags"][..],
        ),
        (
            "sys_enter_migrate_pages",
            &["maxnode", "old_nodes", "new_nodes"][..],
        ),
        (
            "sys_enter_move_pages",
            &["nr_pages", "pages", "nodes", "status", "flags"][..],
        ),
        (
            "sys_enter_set_mempolicy_home_node",
            &["start", "len", "home_node", "flags"][..],
        ),
        ("sys_enter_memfd_create", &["uname", "flags"][..]),
        ("sys_enter_memfd_secret", &["flags"][..]),
        ("sys_enter_utime", &["filename", "times"][..]),
        ("sys_enter_utimes", &["filename", "utimes"][..]),
        ("sys_enter_futimesat", &["dfd", "filename", "utimes"][..]),
        (
            "sys_enter_utimensat",
            &["dfd", "filename", "utimes", "flags"][..],
        ),
        ("sys_enter_time", &["tloc"][..]),
        ("sys_enter_gettimeofday", &["tv", "tz"][..]),
        ("sys_enter_settimeofday", &["tv", "tz"][..]),
        ("sys_enter_adjtimex", &["txc_p"][..]),
        ("sys_enter_getitimer", &["which", "value"][..]),
        ("sys_enter_setitimer", &["which", "value", "ovalue"][..]),
        ("sys_enter_nanosleep", &["rqtp", "rmtp"][..]),
        (
            "sys_enter_timer_create",
            &["which_clock", "timer_event_spec", "created_timer_id"][..],
        ),
        ("sys_enter_timer_gettime", &["timer_id", "setting"][..]),
        ("sys_enter_timer_getoverrun", &["timer_id"][..]),
        (
            "sys_enter_timer_settime",
            &["timer_id", "flags", "new_setting", "old_setting"][..],
        ),
        ("sys_enter_timer_delete", &["timer_id"][..]),
        ("sys_enter_clock_settime", &["which_clock", "tp"][..]),
        ("sys_enter_clock_gettime", &["which_clock", "tp"][..]),
        ("sys_enter_clock_adjtime", &["which_clock", "utx"][..]),
        ("sys_enter_clock_getres", &["which_clock", "tp"][..]),
        (
            "sys_enter_clock_nanosleep",
            &["which_clock", "flags", "rqtp", "rmtp"][..],
        ),
        ("sys_enter_timerfd_create", &["clockid", "flags"][..]),
        (
            "sys_enter_timerfd_settime",
            &["ufd", "flags", "utmr", "otmr"][..],
        ),
        ("sys_enter_timerfd_gettime", &["ufd", "otmr"][..]),
        ("sys_enter_io_uring_setup", &["entries", "params"][..]),
        (
            "sys_enter_io_uring_enter",
            &["fd", "to_submit", "min_complete", "flags", "sig", "sigsz"][..],
        ),
        (
            "sys_enter_io_uring_register",
            &["fd", "opcode", "nr_args"][..],
        ),
        ("sys_enter_io_setup", &["nr_events", "ctxp"][..]),
        ("sys_enter_io_destroy", &["ctx"][..]),
        ("sys_enter_io_submit", &["ctx_id", "nr", "iocbpp"][..]),
        ("sys_enter_io_cancel", &["ctx_id", "iocb", "result"][..]),
        (
            "sys_enter_io_getevents",
            &["ctx_id", "min_nr", "nr", "events", "timeout"][..],
        ),
        (
            "sys_enter_io_pgetevents",
            &["ctx_id", "min_nr", "nr", "events", "timeout", "usig"][..],
        ),
        ("sys_enter_ioprio_set", &["which", "who", "ioprio"][..]),
        ("sys_enter_ioprio_get", &["which", "who"][..]),
        (
            "sys_enter_add_key",
            &["_type", "_description", "_payload", "plen", "ringid"][..],
        ),
        (
            "sys_enter_request_key",
            &["_type", "_description", "_callout_info", "destringid"][..],
        ),
        ("sys_enter_keyctl", &["option"][..]),
        (
            "sys_enter_rt_sigprocmask",
            &["how", "nset", "oset", "sigsetsize"][..],
        ),
        ("sys_enter_rt_sigpending", &["uset", "sigsetsize"][..]),
        (
            "sys_enter_rt_sigtimedwait",
            &["uthese", "uinfo", "uts", "sigsetsize"][..],
        ),
        ("sys_enter_kill", &["sig"][..]),
        ("sys_enter_tkill", &["sig"][..]),
        ("sys_enter_tgkill", &["sig"][..]),
        ("sys_enter_rt_sigqueueinfo", &["sig", "uinfo"][..]),
        ("sys_enter_rt_tgsigqueueinfo", &["sig", "uinfo"][..]),
        ("sys_enter_sigaltstack", &["uss", "uoss"][..]),
        (
            "sys_enter_rt_sigaction",
            &["sig", "act", "oact", "sigsetsize"][..],
        ),
        ("sys_enter_rt_sigsuspend", &["unewset", "sigsetsize"][..]),
        ("sys_enter_signalfd", &["ufd", "user_mask", "sizemask"][..]),
        (
            "sys_enter_signalfd4",
            &["ufd", "user_mask", "sizemask", "flags"][..],
        ),
        ("sys_enter_pidfd_open", &["flags"][..]),
        ("sys_enter_pidfd_getfd", &["pidfd", "fd", "flags"][..]),
        (
            "sys_enter_landlock_create_ruleset",
            &["attr", "size", "flags"][..],
        ),
        (
            "sys_enter_landlock_add_rule",
            &["ruleset_fd", "rule_type", "rule_attr", "flags"][..],
        ),
        (
            "sys_enter_landlock_restrict_self",
            &["ruleset_fd", "flags"][..],
        ),
        ("sys_enter_setpriority", &["which", "who", "niceval"][..]),
        ("sys_enter_getpriority", &["which", "who"][..]),
        ("sys_enter_setregid", &["rgid", "egid"][..]),
        ("sys_enter_setreuid", &["ruid", "euid"][..]),
        ("sys_enter_setresuid", &["ruid", "euid", "suid"][..]),
        ("sys_enter_getresuid", &["ruidp", "euidp", "suidp"][..]),
        ("sys_enter_setresgid", &["rgid", "egid", "sgid"][..]),
        ("sys_enter_getresgid", &["rgidp", "egidp", "sgidp"][..]),
        ("sys_enter_setpgid", &["pgid"][..]),
        ("sys_enter_sethostname", &["name", "len"][..]),
        ("sys_enter_gethostname", &["name", "len"][..]),
        ("sys_enter_setdomainname", &["name", "len"][..]),
        ("sys_enter_getrlimit", &["resource", "rlim"][..]),
        ("sys_enter_setrlimit", &["resource", "rlim"][..]),
        ("sys_enter_getrusage", &["who", "ru"][..]),
        ("sys_enter_umask", &["mask"][..]),
        ("sys_enter_prctl", &["option"][..]),
        ("sys_enter_getcpu", &["cpup", "nodep", "unused"][..]),
        ("sys_enter_getrandom", &["buf", "count", "flags"][..]),
        ("sys_enter_times", &["tbuf"][..]),
        ("sys_enter_newuname", &["name"][..]),
        ("sys_enter_sysinfo", &["info"][..]),
        ("sys_enter_getgroups", &["gidsetsize", "grouplist"][..]),
        ("sys_enter_setgroups", &["gidsetsize", "grouplist"][..]),
        ("sys_enter_capget", &["header", "dataptr"][..]),
        ("sys_enter_capset", &["header", "data"][..]),
        ("sys_enter_nice", &["increment"][..]),
        ("sys_enter_sched_setscheduler", &["policy", "param"][..]),
        ("sys_enter_sched_setparam", &["param"][..]),
        ("sys_enter_sched_setattr", &["uattr", "flags"][..]),
        ("sys_enter_sched_getparam", &["param"][..]),
        ("sys_enter_sched_getattr", &["uattr", "size", "flags"][..]),
        ("sys_enter_sched_setaffinity", &["len", "user_mask_ptr"][..]),
        ("sys_enter_sched_getaffinity", &["len", "user_mask_ptr"][..]),
        ("sys_enter_sched_get_priority_max", &["policy"][..]),
        ("sys_enter_sched_get_priority_min", &["policy"][..]),
        ("sys_enter_sched_rr_get_interval", &["interval"][..]),
        (
            "sys_enter_futex",
            &["uaddr", "op", "val", "utime", "uaddr2", "val3"][..],
        ),
        (
            "sys_enter_mq_open",
            &["u_name", "oflag", "mode", "u_attr"][..],
        ),
        ("sys_enter_mq_unlink", &["u_name"][..]),
        (
            "sys_enter_mq_timedsend",
            &["mqdes", "u_msg_ptr", "msg_len", "msg_prio", "u_abs_timeout"][..],
        ),
        (
            "sys_enter_mq_timedreceive",
            &[
                "mqdes",
                "u_msg_ptr",
                "msg_len",
                "u_msg_prio",
                "u_abs_timeout",
            ][..],
        ),
        ("sys_enter_mq_notify", &["mqdes", "u_notification"][..]),
        (
            "sys_enter_mq_getsetattr",
            &["mqdes", "u_mqstat", "u_omqstat"][..],
        ),
        ("sys_enter_msgget", &["key", "msgflg"][..]),
        ("sys_enter_msgctl", &["msqid", "cmd", "buf"][..]),
        (
            "sys_enter_msgsnd",
            &["msqid", "msgp", "msgsz", "msgflg"][..],
        ),
        (
            "sys_enter_msgrcv",
            &["msqid", "msgp", "msgsz", "msgtyp", "msgflg"][..],
        ),
        ("sys_enter_semget", &["key", "nsems", "semflg"][..]),
        ("sys_enter_semctl", &["semid", "semnum", "cmd"][..]),
        (
            "sys_enter_semtimedop",
            &["semid", "tsops", "nsops", "timeout"][..],
        ),
        ("sys_enter_semop", &["semid", "tsops", "nsops"][..]),
        ("sys_enter_shmget", &["key", "size", "shmflg"][..]),
        ("sys_enter_shmctl", &["shmid", "cmd", "buf"][..]),
        ("sys_enter_shmat", &["shmid", "shmaddr", "shmflg"][..]),
        ("sys_enter_shmdt", &["shmaddr"][..]),
    ] {
        let ctx = TracepointContext::sys_enter(name);
        for field in fields {
            assert!(ctx.has_field(field), "{name} should expose {field}");
        }
    }

    let bind = TracepointContext::sys_enter("sys_enter_bind");
    assert!(matches!(
        bind.get_field("umyaddr")
            .expect("expected bind umyaddr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let getsockopt = TracepointContext::sys_enter("sys_enter_getsockopt");
    assert!(matches!(
        getsockopt
            .get_field("optlen")
            .expect("expected getsockopt optlen")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let kill = TracepointContext::sys_enter("sys_enter_kill");
    assert!(!kill.has_field("pid"));
    assert_eq!(kill.get_field("sig").expect("expected kill sig").offset, 24);

    let rt_tgsigqueueinfo = TracepointContext::sys_enter("sys_enter_rt_tgsigqueueinfo");
    assert!(!rt_tgsigqueueinfo.has_field("tgid"));
    assert!(!rt_tgsigqueueinfo.has_field("pid"));
    assert_eq!(
        rt_tgsigqueueinfo
            .get_field("sig")
            .expect("expected rt_tgsigqueueinfo sig")
            .offset,
        32
    );
    assert_eq!(
        rt_tgsigqueueinfo
            .get_field("uinfo")
            .expect("expected rt_tgsigqueueinfo uinfo")
            .offset,
        40
    );

    let setuid = TracepointContext::sys_enter("sys_enter_setuid");
    assert!(!setuid.has_field("uid"));
    let setpgid = TracepointContext::sys_enter("sys_enter_setpgid");
    assert!(!setpgid.has_field("pid"));
    assert_eq!(
        setpgid
            .get_field("pgid")
            .expect("expected setpgid pgid")
            .offset,
        24
    );
    let prctl = TracepointContext::sys_enter("sys_enter_prctl");
    assert_eq!(
        prctl
            .get_field("option")
            .expect("expected prctl option")
            .offset,
        16
    );
    assert!(!prctl.has_field("arg2"));
    let setgroups = TracepointContext::sys_enter("sys_enter_setgroups");
    assert!(matches!(
        setgroups
            .get_field("grouplist")
            .expect("expected setgroups grouplist")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, setgroups_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_setgroups",
        "grouplist",
    )
    .expect("expected setgroups grouplist source metadata");
    assert!(setgroups_source.contains("/v4.7/kernel/groups.c"));

    let sched_setscheduler = TracepointContext::sys_enter("sys_enter_sched_setscheduler");
    assert!(!sched_setscheduler.has_field("pid"));
    assert_eq!(
        sched_setscheduler
            .get_field("policy")
            .expect("expected sched_setscheduler policy")
            .offset,
        24
    );
    assert!(matches!(
        sched_setscheduler
            .get_field("param")
            .expect("expected sched_setscheduler param")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));
    let (_, sched_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_sched_setscheduler",
        "policy",
    )
    .expect("expected sched_setscheduler policy source metadata");
    assert!(sched_source.contains("/v4.7/kernel/sched/core.c"));

    let sched_getscheduler = TracepointContext::sys_enter("sys_enter_sched_getscheduler");
    assert!(!sched_getscheduler.has_field("pid"));
    let sched_getattr = TracepointContext::sys_enter("sys_enter_sched_getattr");
    assert_eq!(
        sched_getattr
            .get_field("uattr")
            .expect("expected sched_getattr uattr")
            .offset,
        24
    );
    assert!(!sched_getattr.has_field("pid"));

    let semctl = TracepointContext::sys_enter("sys_enter_semctl");
    assert!(!semctl.has_field("arg"));
    assert_eq!(
        semctl.get_field("cmd").expect("expected semctl cmd").offset,
        32
    );
    let (_, semctl_source) = TracepointContext::syscall_fallback_field_minimum_kernel(
        "syscalls",
        "sys_enter_semctl",
        "cmd",
    )
    .expect("expected semctl cmd source metadata");
    assert!(semctl_source.contains("/v4.7/ipc/sem.c"));

    let msgrcv = TracepointContext::sys_enter("sys_enter_msgrcv");
    assert_eq!(
        msgrcv
            .get_field("msgtyp")
            .expect("expected msgrcv msgtyp")
            .offset,
        40
    );
    assert!(matches!(
        msgrcv
            .get_field("msgp")
            .expect("expected msgrcv msgp")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let shmat = TracepointContext::sys_enter("sys_enter_shmat");
    assert!(matches!(
        shmat
            .get_field("shmaddr")
            .expect("expected shmat shmaddr")
            .type_info,
        TypeInfo::Ptr { is_user: true, .. }
    ));

    let unknown = TracepointContext::sys_enter("sys_enter_unknown");
    assert!(unknown.has_field("id"));
    assert!(unknown.has_field("args"));
    assert!(!unknown.has_field("filename"));
}

#[test]
fn test_wellknown_sys_exit() {
    let read = TracepointContext::sys_exit("sys_exit_read");
    assert_eq!(read.category, "syscalls");
    assert_eq!(
        read.source,
        TracepointContextSource::WellKnownSyscallFallback
    );
    assert_eq!(read.minimum_kernel(), Some("4.7"));
    assert!(
        read.minimum_kernel_source()
            .is_some_and(|source| source.contains("/v4.7/include/trace/events/syscalls.h"))
    );
    assert!(read.has_field("id"));
    assert!(read.has_field("ret"));
    assert_eq!(read.get_field("id").expect("expected id").offset, 8);
    assert_eq!(read.get_field("ret").expect("expected ret").offset, 16);

    let openat2 = TracepointContext::sys_exit("sys_exit_openat2");
    assert_eq!(openat2.minimum_kernel(), Some("5.6"));
    assert!(
        openat2
            .minimum_kernel_source()
            .is_some_and(|source| source.contains("/v5.6/fs/open.c"))
    );
    assert!(openat2.has_field("id"));
    assert!(openat2.has_field("ret"));
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
    assert_eq!(
        KernelBtf::infer_pointer_ref_family("xfrm_state"),
        Some(KfuncPointerRefFamily::XfrmState)
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

fn find_kfunc_callback_signature_hint_candidate() -> Option<(&'static str, usize)> {
    for candidate in [
        ("bpf_rbtree_add_impl", 2usize),
        ("bpf_wq_set_callback_impl", 1usize),
    ] {
        if KernelBtf::get().kfunc_signature_hint(candidate.0).is_some() {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn test_kfunc_signature_hint_marks_function_pointer_args_as_subprograms() {
    let Some((kfunc, callback_idx)) = find_kfunc_callback_signature_hint_candidate() else {
        return;
    };

    let hint = KernelBtf::get()
        .kfunc_signature_hint(kfunc)
        .expect("candidate kfunc signature should be available");

    assert_eq!(hint.arg_shapes[callback_idx], KfuncArgShape::Subprogram);
}

#[test]
fn test_kfunc_callback_arg_type_infos_resolves_function_pointer_candidate() {
    let Some((kfunc, callback_idx)) = find_kfunc_callback_signature_hint_candidate() else {
        return;
    };

    let args = KernelBtf::get()
        .kfunc_callback_arg_type_infos(kfunc, callback_idx)
        .expect("candidate callback prototype query should succeed")
        .expect("candidate callback prototype should have arguments");

    assert!(!args.is_empty());
    assert!(matches!(
        args.first(),
        Some(TypeInfo::Ptr { .. } | TypeInfo::Int { .. })
    ));
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
