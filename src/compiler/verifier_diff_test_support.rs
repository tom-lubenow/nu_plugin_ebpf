use std::fs;
use std::path::{Path, PathBuf};

const VERIFIER_DIFF_ENTRYPOINT: &str = "scripts/verifier_diff.nu";
const VERIFIER_DIFF_FIXTURES: &str = "scripts/verifier_diff/fixtures.nu";
const VERIFIER_DIFF_PROGRAM_CONTEXT_FIELD_EXPECTATION_CHUNKS_DIR: &str =
    "scripts/verifier_diff/metadata/expectations/program_context_fields";

const VERIFIER_DIFF_METADATA_SOURCES: &[&str] = &[
    "scripts/verifier_diff/metadata/core_features.nu",
    "scripts/verifier_diff/metadata/core_runtime_config.nu",
    "scripts/verifier_diff/metadata/core_program_features.nu",
    "scripts/verifier_diff/metadata/core_program_xdp_features.nu",
    "scripts/verifier_diff/metadata/core_program_network_features.nu",
    "scripts/verifier_diff/metadata/core_program_struct_ops_features.nu",
    "scripts/verifier_diff/metadata/core_program_cgroup_struct_features.nu",
    "scripts/verifier_diff/metadata/core_iter_network_features.nu",
    "scripts/verifier_diff/metadata/core_iter_features.nu",
    "scripts/verifier_diff/metadata/core_program_target_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_language_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_map_redirect_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_map_storage_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_map_helper_storage_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_map_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_map_value_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_global_context_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_global_literal_data_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_global_mutable_data_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_global_data_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_global_expectations.nu",
    "scripts/verifier_diff/metadata/core_basic_map_features.nu",
    "scripts/verifier_diff/metadata/core_map_features.nu",
    "scripts/verifier_diff/metadata/core_network_map_features.nu",
    "scripts/verifier_diff/metadata/core_special_map_features.nu",
    "scripts/verifier_diff/metadata/core_map_helper_features.nu",
    "scripts/verifier_diff/metadata/core_context_helper_features.nu",
    "scripts/verifier_diff/metadata/core_cgroup_socket_helper_features.nu",
    "scripts/verifier_diff/metadata/core_ringbuf_helper_features.nu",
    "scripts/verifier_diff/metadata/core_probe_perf_helper_features.nu",
    "scripts/verifier_diff/metadata/core_helper_features.nu",
    "scripts/verifier_diff/metadata/core_socket_sysctl_helper_features.nu",
    "scripts/verifier_diff/metadata/core_xdp_packet_helper_features.nu",
    "scripts/verifier_diff/metadata/core_packet_helper_features.nu",
    "scripts/verifier_diff/metadata/core_stream_msg_helper_features.nu",
    "scripts/verifier_diff/metadata/core_skb_socket_redirect_helper_features.nu",
    "scripts/verifier_diff/metadata/core_stream_timer_dynptr_features.nu",
    "scripts/verifier_diff/metadata/core_dynptr_helper_features.nu",
    "scripts/verifier_diff/metadata/core_map_value_kfunc_features.nu",
    "scripts/verifier_diff/metadata/core_task_cgroup_kfunc_features.nu",
    "scripts/verifier_diff/metadata/core_cpumask_kfunc_features.nu",
    "scripts/verifier_diff/metadata/core_object_kfunc_features.nu",
    "scripts/verifier_diff/metadata/core_sched_ext_kfunc_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_syscall_io_field_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_syscall_open_exec_field_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_core_field_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_file_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_file_data_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_socket_lifecycle_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_socket_message_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_socket_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_namei_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_path_location_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_path_stat_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_path_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_mount_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_path_xattr_mount_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_process_lifecycle_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_process_system_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_process_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_pidfd_signal_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_signal_sched_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_sched_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_futex_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_quota_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_mqueue_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_ipc_arch_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_x86_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_epoll_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_notify_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_poll_select_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_event_poll_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_fd_file_op_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_fd_descriptor_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_fd_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_mempolicy_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_virtual_memory_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_mm_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_posix_time_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_time_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_io_security_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_security_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_system_resource_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_system_misc_control_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_system_control_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_privilege_control_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_identity_features.nu",
    "scripts/verifier_diff/metadata/context_features.nu",
    "scripts/verifier_diff/metadata/context_packet_base_field_features.nu",
    "scripts/verifier_diff/metadata/context_packet_field_features.nu",
    "scripts/verifier_diff/metadata/context_cgroup_socket_field_features.nu",
    "scripts/verifier_diff/metadata/context_xdp_field_features.nu",
    "scripts/verifier_diff/metadata/context_network_field_features.nu",
    "scripts/verifier_diff/metadata/context_sk_lookup_field_features.nu",
    "scripts/verifier_diff/metadata/context_sock_addr_field_features.nu",
    "scripts/verifier_diff/metadata/context_sock_msg_field_features.nu",
    "scripts/verifier_diff/metadata/context_sk_msg_field_features.nu",
    "scripts/verifier_diff/metadata/context_iter_network_field_features.nu",
    "scripts/verifier_diff/metadata/context_iter_task_field_features.nu",
    "scripts/verifier_diff/metadata/context_iter_map_socket_field_features.nu",
    "scripts/verifier_diff/metadata/context_iter_field_features.nu",
    "scripts/verifier_diff/metadata/context_sk_reuseport_field_features.nu",
    "scripts/verifier_diff/metadata/context_socket_field_features.nu",
    "scripts/verifier_diff/metadata/context_generic_field_features.nu",
    "scripts/verifier_diff/metadata/context_time_perf_field_features.nu",
    "scripts/verifier_diff/metadata/context_sysctl_field_features.nu",
    "scripts/verifier_diff/metadata/context_sockopt_field_features.nu",
    "scripts/verifier_diff/metadata/context_socket_control_field_features.nu",
    "scripts/verifier_diff/metadata/context_return_stack_field_features.nu",
    "scripts/verifier_diff/metadata/context_map_kind_features.nu",
    "scripts/verifier_diff/metadata/context_map_value_features.nu",
    "scripts/verifier_diff/metadata/context_map_features.nu",
    "scripts/verifier_diff/metadata/context_bpf_helper_ids_event_timer.nu",
    "scripts/verifier_diff/metadata/context_bpf_helper_ids_socket_packet.nu",
    "scripts/verifier_diff/metadata/context_bpf_helper_ids_network_misc.nu",
    "scripts/verifier_diff/metadata/context_bpf_helper_ids.nu",
    "scripts/verifier_diff/metadata/context_helper_floor_features.nu",
    "scripts/verifier_diff/metadata/context_basic_helper_features.nu",
    "scripts/verifier_diff/metadata/context_probe_perf_helper_features.nu",
    "scripts/verifier_diff/metadata/context_packet_socket_helper_features.nu",
    "scripts/verifier_diff/metadata/context_runtime_object_helper_features.nu",
    "scripts/verifier_diff/metadata/context_helper_features.nu",
    "scripts/verifier_diff/metadata/context_kfunc_helper_features.nu",
    "scripts/verifier_diff/metadata/context_sched_ext_kfunc_fallbacks.nu",
    "scripts/verifier_diff/metadata/context_cpumask_kfunc_fallbacks.nu",
    "scripts/verifier_diff/metadata/context_object_dynptr_kfunc_fallbacks.nu",
    "scripts/verifier_diff/metadata/context_iter_kfunc_fallbacks.nu",
    "scripts/verifier_diff/metadata/context_kfunc_fallbacks.nu",
    "scripts/verifier_diff/metadata/context_identity_field_features.nu",
    "scripts/verifier_diff/metadata/context_feature_tables.nu",
    "scripts/verifier_diff/metadata/expectations.nu",
    "scripts/verifier_diff/metadata/expectations/context_fields.nu",
    "scripts/verifier_diff/metadata/expectations/context_field_helpers.nu",
    "scripts/verifier_diff/metadata/expectations/context_projection_helpers.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_socket_redirect.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_packet_socket.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_tc_socket_write.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_sock_ops_write.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_socket_write.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_tc_context_write.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_sysctl_context_write.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_context_write.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_task_storage.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_object_storage.nu",
    "scripts/verifier_diff/metadata/expectations/program_surface_storage.nu",
    "scripts/verifier_diff/metadata/expectations/program_surfaces.nu",
    "scripts/verifier_diff/metadata/expectations/program_helper_core.nu",
    "scripts/verifier_diff/metadata/expectations/program_helper_socket.nu",
    "scripts/verifier_diff/metadata/expectations/program_helper_timer.nu",
    "scripts/verifier_diff/metadata/expectations/program_helpers.nu",
    "scripts/verifier_diff/metadata/expectations/program_kfunc_sock_addr.nu",
    "scripts/verifier_diff/metadata/expectations/program_kfuncs.nu",
    "scripts/verifier_diff/metadata/expectations/program_kfunc_details.nu",
    "scripts/verifier_diff/metadata/expectations/program_callbacks.nu",
];

const VERIFIER_DIFF_RUNTIME_SOURCES: &[&str] = &[
    "scripts/verifier_diff/runtime/core.nu",
    "scripts/verifier_diff/runtime/source_text.nu",
    "scripts/verifier_diff/runtime/source_text_tokens.nu",
    "scripts/verifier_diff/runtime/source_text_commands.nu",
    "scripts/verifier_diff/runtime/source_text_map_helpers.nu",
    "scripts/verifier_diff/runtime/source_text_kernel_features.nu",
    "scripts/verifier_diff/runtime/context_fields.nu",
    "scripts/verifier_diff/runtime/context_target_fields_socket.nu",
    "scripts/verifier_diff/runtime/context_target_fields_cgroup_misc.nu",
    "scripts/verifier_diff/runtime/context_target_fields_iter.nu",
    "scripts/verifier_diff/runtime/context_target_fields.nu",
    "scripts/verifier_diff/runtime/context_projection_roots.nu",
    "scripts/verifier_diff/runtime/context_field_kernel_features.nu",
    "scripts/verifier_diff/runtime/context_field_write_detection.nu",
    "scripts/verifier_diff/runtime/context_projection_kernel_features.nu",
    "scripts/verifier_diff/runtime/context_roots.nu",
    "scripts/verifier_diff/runtime/context_root_value_tokens.nu",
    "scripts/verifier_diff/runtime/context_root_wrapper_invocations.nu",
    "scripts/verifier_diff/runtime/context_record_literals.nu",
    "scripts/verifier_diff/runtime/context_record_parse_helpers.nu",
    "scripts/verifier_diff/runtime/context_record_flows.nu",
    "scripts/verifier_diff/runtime/context_root_bindings.nu",
    "scripts/verifier_diff/runtime/context_record_field_ops.nu",
    "scripts/verifier_diff/runtime/context_record_bindings.nu",
    "scripts/verifier_diff/runtime/context_function_wrappers.nu",
    "scripts/verifier_diff/runtime/context_multi_param_functions.nu",
    "scripts/verifier_diff/runtime/context_variable_names.nu",
    "scripts/verifier_diff/runtime/context_function_roots.nu",
    "scripts/verifier_diff/runtime/context_source_parsing.nu",
    "scripts/verifier_diff/runtime/context_projection_alias_features.nu",
    "scripts/verifier_diff/runtime/context_projection_features.nu",
    "scripts/verifier_diff/runtime/context_projection_get_features.nu",
    "scripts/verifier_diff/runtime/tracepoint_field_features.nu",
    "scripts/verifier_diff/runtime/program_target_features.nu",
    "scripts/verifier_diff/runtime/program_features.nu",
    "scripts/verifier_diff/runtime/program_global_features.nu",
    "scripts/verifier_diff/runtime/program_callback_features.nu",
    "scripts/verifier_diff/runtime/program_surface_features.nu",
    "scripts/verifier_diff/runtime/matrix_validation.nu",
    "scripts/verifier_diff/runtime/matrix_rows.nu",
    "scripts/verifier_diff/runtime/matrix_metadata_validation.nu",
    "scripts/verifier_diff/runtime/execution.nu",
    "scripts/verifier_diff/runtime/cli_options.nu",
];

pub(crate) fn verifier_diff_metadata_source() -> String {
    let mut source = String::new();
    append_verifier_diff_metadata_sources(&mut source);
    source
}

pub(crate) fn verifier_diff_source() -> String {
    verifier_diff_source_inner(false)
}

pub(crate) fn verifier_diff_source_with_fixture_chunks() -> String {
    verifier_diff_source_inner(true)
}

fn verifier_diff_source_inner(include_fixture_chunks: bool) -> String {
    let mut source = String::new();
    append_verifier_diff_source(
        &mut source,
        VERIFIER_DIFF_ENTRYPOINT,
        "verifier diff entrypoint",
    );
    append_verifier_diff_metadata_sources(&mut source);
    append_verifier_diff_source(
        &mut source,
        VERIFIER_DIFF_FIXTURES,
        "verifier diff fixtures",
    );
    if include_fixture_chunks {
        append_verifier_diff_fixture_chunks(&mut source);
    }
    append_verifier_diff_source_files(
        &mut source,
        VERIFIER_DIFF_RUNTIME_SOURCES,
        "verifier diff runtime",
    );
    source
}

fn append_verifier_diff_metadata_sources(source: &mut String) {
    append_verifier_diff_source_files(
        source,
        VERIFIER_DIFF_METADATA_SOURCES,
        "verifier diff metadata",
    );
    append_verifier_diff_source_paths(
        source,
        verifier_diff_program_context_field_expectation_chunk_paths(),
        "verifier diff program context-field expectation",
    );
}

fn append_verifier_diff_source_files(source: &mut String, relatives: &[&str], label: &str) {
    for relative in relatives {
        append_verifier_diff_source(source, relative, label);
    }
}

fn append_verifier_diff_source_paths<I>(source: &mut String, paths: I, label: &str)
where
    I: IntoIterator<Item = PathBuf>,
{
    for path in paths {
        source.push_str(
            &fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("failed to read {label} {}: {err}", path.display())),
        );
        source.push('\n');
    }
}

fn append_verifier_diff_source(source: &mut String, relative: &str, label: &str) {
    let path = manifest_dir().join(relative);
    source.push_str(
        &fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("failed to read {label} source {}: {err}", path.display())
        }),
    );
    source.push('\n');
}

fn append_verifier_diff_fixture_chunks(source: &mut String) {
    append_verifier_diff_source_paths(
        source,
        verifier_diff_fixture_chunk_paths(),
        "verifier diff fixture",
    );
}

fn verifier_diff_fixture_chunk_paths() -> Vec<PathBuf> {
    verifier_diff_chunk_paths("scripts/verifier_diff/fixtures", "fixtures_")
}

fn verifier_diff_program_context_field_expectation_chunk_paths() -> Vec<PathBuf> {
    verifier_diff_chunk_paths(
        VERIFIER_DIFF_PROGRAM_CONTEXT_FIELD_EXPECTATION_CHUNKS_DIR,
        "program_context_fields_",
    )
}

fn verifier_diff_chunk_paths(relative_dir: &str, file_prefix: &str) -> Vec<PathBuf> {
    let chunk_dir = manifest_dir().join(relative_dir);
    let mut chunk_paths = fs::read_dir(&chunk_dir)
        .unwrap_or_else(|err| {
            panic!(
                "failed to read verifier diff chunk directory {}: {err}",
                chunk_dir.display()
            )
        })
        .map(|entry| {
            entry
                .unwrap_or_else(|err| panic!("failed to read verifier diff fixture entry: {err}"))
                .path()
        })
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(file_prefix) && name.ends_with(".nu"))
        })
        .collect::<Vec<_>>();
    chunk_paths.sort();
    chunk_paths
}

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
