use std::fs;
use std::path::{Path, PathBuf};

const VERIFIER_DIFF_ENTRYPOINT: &str = "scripts/verifier_diff.nu";
const VERIFIER_DIFF_FIXTURES: &str = "scripts/verifier_diff/fixtures.nu";

const VERIFIER_DIFF_METADATA_SOURCES: &[&str] = &[
    "scripts/verifier_diff/metadata/core_features.nu",
    "scripts/verifier_diff/metadata/core_program_map_expectations.nu",
    "scripts/verifier_diff/metadata/core_program_global_expectations.nu",
    "scripts/verifier_diff/metadata/core_map_features.nu",
    "scripts/verifier_diff/metadata/core_map_helper_features.nu",
    "scripts/verifier_diff/metadata/core_context_helper_features.nu",
    "scripts/verifier_diff/metadata/core_helper_features.nu",
    "scripts/verifier_diff/metadata/core_map_value_kfunc_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_file_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_socket_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_path_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_fd_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_mm_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_time_features.nu",
    "scripts/verifier_diff/metadata/tracepoint_identity_features.nu",
    "scripts/verifier_diff/metadata/context_features.nu",
    "scripts/verifier_diff/metadata/context_packet_field_features.nu",
    "scripts/verifier_diff/metadata/context_network_field_features.nu",
    "scripts/verifier_diff/metadata/context_sock_addr_field_features.nu",
    "scripts/verifier_diff/metadata/context_sock_msg_field_features.nu",
    "scripts/verifier_diff/metadata/context_iter_field_features.nu",
    "scripts/verifier_diff/metadata/context_socket_field_features.nu",
    "scripts/verifier_diff/metadata/context_generic_field_features.nu",
    "scripts/verifier_diff/metadata/context_bpf_helper_ids.nu",
    "scripts/verifier_diff/metadata/expectations.nu",
    "scripts/verifier_diff/metadata/expectations/context_fields.nu",
    "scripts/verifier_diff/metadata/expectations/program_context_fields_1.nu",
    "scripts/verifier_diff/metadata/expectations/program_context_fields_2.nu",
    "scripts/verifier_diff/metadata/expectations/program_context_fields_3.nu",
    "scripts/verifier_diff/metadata/expectations/program_context_fields_4.nu",
    "scripts/verifier_diff/metadata/expectations/program_surfaces.nu",
    "scripts/verifier_diff/metadata/expectations/program_helpers.nu",
    "scripts/verifier_diff/metadata/expectations/program_kfuncs.nu",
    "scripts/verifier_diff/metadata/expectations/program_callbacks.nu",
];

const VERIFIER_DIFF_RUNTIME_SOURCES: &[&str] = &[
    "scripts/verifier_diff/runtime/core.nu",
    "scripts/verifier_diff/runtime/source_text.nu",
    "scripts/verifier_diff/runtime/source_text_commands.nu",
    "scripts/verifier_diff/runtime/context_fields.nu",
    "scripts/verifier_diff/runtime/context_target_fields.nu",
    "scripts/verifier_diff/runtime/context_projection_roots.nu",
    "scripts/verifier_diff/runtime/context_roots.nu",
    "scripts/verifier_diff/runtime/context_root_value_tokens.nu",
    "scripts/verifier_diff/runtime/context_record_flows.nu",
    "scripts/verifier_diff/runtime/context_record_field_ops.nu",
    "scripts/verifier_diff/runtime/context_function_wrappers.nu",
    "scripts/verifier_diff/runtime/context_multi_param_functions.nu",
    "scripts/verifier_diff/runtime/context_variable_names.nu",
    "scripts/verifier_diff/runtime/context_function_roots.nu",
    "scripts/verifier_diff/runtime/context_source_parsing.nu",
    "scripts/verifier_diff/runtime/context_projection_features.nu",
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
    read_verifier_diff_source_files(VERIFIER_DIFF_METADATA_SOURCES, "verifier diff metadata")
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
    append_verifier_diff_source_files(
        &mut source,
        VERIFIER_DIFF_METADATA_SOURCES,
        "verifier diff metadata",
    );
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

fn read_verifier_diff_source_files(relatives: &[&str], label: &str) -> String {
    let mut source = String::new();
    append_verifier_diff_source_files(&mut source, relatives, label);
    source
}

fn append_verifier_diff_source_files(source: &mut String, relatives: &[&str], label: &str) {
    for relative in relatives {
        append_verifier_diff_source(source, relative, label);
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
    for path in verifier_diff_fixture_chunk_paths() {
        source.push_str(&fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "failed to read verifier diff fixture {}: {err}",
                path.display()
            )
        }));
        source.push('\n');
    }
}

fn verifier_diff_fixture_chunk_paths() -> Vec<PathBuf> {
    let fixture_dir = manifest_dir().join("scripts/verifier_diff/fixtures");
    let mut fixture_paths = fs::read_dir(&fixture_dir)
        .unwrap_or_else(|err| {
            panic!(
                "failed to read verifier diff fixture directory {}: {err}",
                fixture_dir.display()
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
                .is_some_and(|name| name.starts_with("fixtures_") && name.ends_with(".nu"))
        })
        .collect::<Vec<_>>();
    fixture_paths.sort();
    fixture_paths
}

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
