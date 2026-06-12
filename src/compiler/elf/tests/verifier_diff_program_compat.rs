use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::CtxField;
use crate::compiler::{
    CompiledFeatureCompatibilityRequirement, ContextFieldCompatibilityRequirement, EbpfProgramType,
    GlobalCompatibilityRequirement, HelperCompatibilityRequirement, KfuncCompatibilityRequirement,
    MapKind, MapValueCompatibilityRequirement, ProgramCompatibilityRequirement,
};
use crate::kernel_btf::TracepointContext;
use crate::program_spec::{IterTargetKind, ProgramSpec};

static NU_SCRIPT_COUNTER: AtomicU64 = AtomicU64::new(0);

const VERIFIER_DIFF_SOURCE: &str = concat!(
    include_str!("../../../../scripts/verifier_diff.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/core_features.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/tracepoint_features.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/context_features.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/expectations.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/expectations/context_fields.nu"),
    "\n",
    include_str!(
        "../../../../scripts/verifier_diff/metadata/expectations/program_context_fields_1.nu"
    ),
    "\n",
    include_str!(
        "../../../../scripts/verifier_diff/metadata/expectations/program_context_fields_2.nu"
    ),
    "\n",
    include_str!(
        "../../../../scripts/verifier_diff/metadata/expectations/program_context_fields_3.nu"
    ),
    "\n",
    include_str!(
        "../../../../scripts/verifier_diff/metadata/expectations/program_context_fields_4.nu"
    ),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/expectations/program_surfaces.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/expectations/program_helpers.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/expectations/program_kfuncs.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/metadata/expectations/program_callbacks.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/runtime/core.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/runtime/source_text.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/runtime/context_fields.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/runtime/context_roots.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/runtime/program_features.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/runtime/matrix_validation.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/runtime/execution.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/runtime/cli_options.nu"),
);

fn verifier_diff_source_with_fixtures() -> String {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut source = String::new();

    for relative in [
        "scripts/verifier_diff.nu",
        "scripts/verifier_diff/metadata/core_features.nu",
        "scripts/verifier_diff/metadata/tracepoint_features.nu",
        "scripts/verifier_diff/metadata/context_features.nu",
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
        "scripts/verifier_diff/fixtures.nu",
    ] {
        let path = manifest_dir.join(relative);
        source.push_str(&fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "failed to read verifier diff source {}: {err}",
                path.display()
            )
        }));
        source.push('\n');
    }

    let fixture_dir = manifest_dir.join("scripts/verifier_diff/fixtures");
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

    for path in fixture_paths {
        source.push_str(&fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "failed to read verifier diff fixture {}: {err}",
                path.display()
            )
        }));
        source.push('\n');
    }

    for relative in [
        "scripts/verifier_diff/runtime/core.nu",
        "scripts/verifier_diff/runtime/source_text.nu",
        "scripts/verifier_diff/runtime/context_fields.nu",
        "scripts/verifier_diff/runtime/context_roots.nu",
        "scripts/verifier_diff/runtime/program_features.nu",
        "scripts/verifier_diff/runtime/matrix_validation.nu",
        "scripts/verifier_diff/runtime/execution.nu",
        "scripts/verifier_diff/runtime/cli_options.nu",
    ] {
        let path = manifest_dir.join(relative);
        source.push_str(&fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "failed to read verifier diff runtime source {}: {err}",
                path.display()
            )
        }));
        source.push('\n');
    }

    source
}

const REPRESENTATIVE_CONTEXT_WRITE_SPEC_SOURCES: &[&str] = &[
    "socket_filter:udp4:127.0.0.1:31337",
    "tc:lo:ingress",
    "tc:lo:egress",
    "tcx:lo:ingress",
    "tcx:lo:egress",
    "netkit:lo:primary",
    "netkit:lo:peer",
    "tc_action:diff-action",
    "sk_skb:/sys/fs/bpf/demo_sockmap",
    "sk_skb_parser:/sys/fs/bpf/demo_sockmap",
    "lwt_in:demo-route",
    "lwt_out:demo-route",
    "lwt_xmit:demo-route",
    "lwt_seg6local:demo-route",
    "cgroup_skb:/sys/fs/cgroup:ingress",
    "cgroup_skb:/sys/fs/cgroup:egress",
    "cgroup_sock:/sys/fs/cgroup:sock_create",
    "cgroup_sock:/sys/fs/cgroup:post_bind4",
    "cgroup_sysctl:/sys/fs/cgroup",
    "sock_ops:/sys/fs/cgroup",
    "cgroup_sockopt:/sys/fs/cgroup:get",
    "cgroup_sockopt:/sys/fs/cgroup:set",
    "cgroup_sock_addr:/sys/fs/cgroup:connect4",
    "cgroup_sock_addr:/sys/fs/cgroup:connect6",
    "cgroup_sock_addr:/sys/fs/cgroup:sendmsg4",
    "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6",
    "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
    "sk_lookup:/proc/self/ns/net",
    "flow_dissector:/proc/self/ns/net",
];

fn run_nu_script(script: &str, label: &str) -> Option<Output> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_nanos();
    let sequence = NU_SCRIPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let script_path = std::env::temp_dir().join(format!(
        "nu_plugin_ebpf_verifier_diff_{}_{}_{}.nu",
        std::process::id(),
        unique,
        sequence
    ));
    let verifier_diff_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/verifier_diff.nu");
    let script = script.replace(
        "source scripts/verifier_diff.nu",
        &format!("source {}", verifier_diff_path.display()),
    );
    fs::write(&script_path, script)
        .unwrap_or_else(|err| panic!("failed to write temporary Nu script for {label}: {err}"));

    let output = Command::new("nu")
        .arg(&script_path)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("VERIFIER_DIFF_SOURCE_ONLY", "1")
        .output();
    let _ = fs::remove_file(&script_path);

    match output {
        Ok(output) => Some(output),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping verifier_diff.nu {label}: nu binary was not found");
            None
        }
        Err(err) => panic!("failed to run nu for verifier_diff.nu {label}: {err}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifierDiffFeatureRecord {
    key: String,
    min_kernel: String,
    source: String,
    max_kernel_exclusive: Option<String>,
    max_kernel_exclusive_source: Option<String>,
}

fn verifier_diff_const_body<'a>(source: &'a str, name: &str, delimiter: char) -> &'a str {
    let start_delimiter = format!("const {name} = {delimiter}");
    let start = source
        .find(&start_delimiter)
        .unwrap_or_else(|| panic!("expected scripts/verifier_diff.nu const {name}"))
        + start_delimiter.len();
    let end_delimiter = match delimiter {
        '[' => "\n]",
        '{' => "\n}",
        _ => panic!("unsupported verifier_diff.nu delimiter {delimiter}"),
    };
    let rest = &source[start..];
    let end = rest.find(end_delimiter).unwrap_or_else(|| {
        panic!("expected scripts/verifier_diff.nu const {name} to close with {end_delimiter:?}")
    });
    &rest[..end]
}

fn verifier_diff_quoted_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("{field}: \"");
    let rest = verifier_diff_field_rest(text, &needle)?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn verifier_diff_dollar_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("{field}: $");
    let rest = verifier_diff_field_rest(text, &needle)?;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '}')
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

fn verifier_diff_field_rest<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    let mut offset = 0;
    while let Some(relative_index) = text[offset..].find(needle) {
        let index = offset + relative_index;
        let field_start = match text[..index].chars().next_back() {
            Some(c) => !(c == '_' || c.is_ascii_alphanumeric()),
            None => true,
        };
        if field_start {
            return Some(&text[index + needle.len()..]);
        }
        offset = index + 1;
    }
    None
}

fn verifier_diff_feature_record(source: &str, const_name: &str) -> VerifierDiffFeatureRecord {
    let body = verifier_diff_const_body(source, const_name, '{');
    VerifierDiffFeatureRecord {
        key: verifier_diff_quoted_field(body, "key")
            .unwrap_or_else(|| panic!("{const_name} should declare key"))
            .to_string(),
        min_kernel: verifier_diff_quoted_field(body, "min_kernel")
            .unwrap_or_else(|| panic!("{const_name} should declare min_kernel"))
            .to_string(),
        source: verifier_diff_quoted_field(body, "source")
            .unwrap_or_else(|| panic!("{const_name} should declare source"))
            .to_string(),
        max_kernel_exclusive: verifier_diff_quoted_field(body, "max_kernel_exclusive")
            .map(str::to_string),
        max_kernel_exclusive_source: verifier_diff_quoted_field(
            body,
            "max_kernel_exclusive_source",
        )
        .map(str::to_string),
    }
}

fn verifier_diff_program_feature_records(
    source: &str,
) -> BTreeMap<String, VerifierDiffFeatureRecord> {
    let end = source
        .find("const KERNEL_FEATURE_MAP_HASH")
        .expect("expected map kernel features to follow program kernel features");
    let program_feature_source = &source[..end];
    let mut records = BTreeMap::new();

    for line in program_feature_source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("const KERNEL_FEATURE_") {
            continue;
        }
        let const_name = trimmed
            .strip_prefix("const ")
            .and_then(|rest| rest.split_whitespace().next())
            .expect("kernel feature const declaration should expose its name");
        let record = verifier_diff_feature_record(source, const_name);
        assert!(
            records.insert(record.key.clone(), record).is_none(),
            "duplicate scripts/verifier_diff.nu program kernel feature key in {const_name}"
        );
    }

    records
}

fn verifier_diff_feature_table_records(
    source: &str,
    const_name: &str,
    table_key_field: &str,
) -> BTreeMap<String, VerifierDiffFeatureRecord> {
    let body = verifier_diff_const_body(source, const_name, '[');
    let mut records = BTreeMap::new();

    for line in body.lines() {
        let Some(table_key) = verifier_diff_quoted_field(line, table_key_field) else {
            continue;
        };
        let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
            panic!("{const_name} entry {table_key} should reference a feature const")
        });
        let record = verifier_diff_feature_record(source, feature_const);
        assert!(
            records.insert(table_key.to_string(), record).is_none(),
            "duplicate scripts/verifier_diff.nu {const_name} entry for {table_key}"
        );
    }

    records
}

fn verifier_diff_kfunc_fallback_records(
    source: &str,
) -> BTreeMap<String, VerifierDiffFeatureRecord> {
    let body = verifier_diff_const_body(source, "KFUNC_KERNEL_FEATURE_FALLBACKS", '[');
    let mut records = BTreeMap::new();

    for line in body.lines() {
        let Some(name) = verifier_diff_quoted_field(line, "name") else {
            continue;
        };
        let min_kernel = verifier_diff_quoted_field(line, "min_kernel").unwrap_or_else(|| {
            panic!("KFUNC_KERNEL_FEATURE_FALLBACKS entry {name} missing min_kernel")
        });
        let source = verifier_diff_quoted_field(line, "source").unwrap_or_else(|| {
            panic!("KFUNC_KERNEL_FEATURE_FALLBACKS entry {name} missing source")
        });
        let record = VerifierDiffFeatureRecord {
            key: format!("kfunc:{name}"),
            min_kernel: min_kernel.to_string(),
            source: source.to_string(),
            max_kernel_exclusive: verifier_diff_quoted_field(line, "max_kernel_exclusive")
                .map(str::to_string),
            max_kernel_exclusive_source: verifier_diff_quoted_field(
                line,
                "max_kernel_exclusive_source",
            )
            .map(str::to_string),
        };
        assert!(
            records.insert(name.to_string(), record).is_none(),
            "duplicate scripts/verifier_diff.nu KFUNC_KERNEL_FEATURE_FALLBACKS entry for {name}"
        );
    }

    records
}

#[derive(Debug, Clone)]
struct VerifierDiffTargetContextFeatureRecord {
    target: String,
    field: String,
    feature: VerifierDiffFeatureRecord,
}

fn verifier_diff_target_context_field_feature_records(
    source: &str,
) -> Vec<VerifierDiffTargetContextFeatureRecord> {
    let body = verifier_diff_const_body(
        source,
        "TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS",
        '[',
    );
    let mut records = Vec::new();

    for line in body.lines() {
        let Some(target) = verifier_diff_quoted_field(line, "target") else {
            continue;
        };
        let field = verifier_diff_quoted_field(line, "field").unwrap_or_else(|| {
            panic!("TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS target {target} missing field")
        });
        let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
            panic!(
                "TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS target {target} field {field} should reference a feature const"
            )
        });

        records.push(VerifierDiffTargetContextFeatureRecord {
            target: target.to_string(),
            field: field.to_string(),
            feature: verifier_diff_feature_record(source, feature_const),
        });
    }

    records
}

fn verifier_diff_tracepoint_field_feature_records(
    source: &str,
) -> Vec<VerifierDiffTargetContextFeatureRecord> {
    let body = verifier_diff_const_body(source, "TRACEPOINT_FIELD_KERNEL_FEATURES", '[');
    let mut records = Vec::new();

    for line in body.lines() {
        let Some(target) = verifier_diff_quoted_field(line, "target") else {
            continue;
        };
        let field = verifier_diff_quoted_field(line, "field").unwrap_or_else(|| {
            panic!("TRACEPOINT_FIELD_KERNEL_FEATURES target {target} missing field")
        });
        let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
            panic!(
                "TRACEPOINT_FIELD_KERNEL_FEATURES target {target} field {field} should reference a feature const"
            )
        });

        records.push(VerifierDiffTargetContextFeatureRecord {
            target: target.to_string(),
            field: field.to_string(),
            feature: verifier_diff_feature_record(source, feature_const),
        });
    }

    records
}

fn verifier_diff_quoted_strings(text: &str) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('"') else {
            break;
        };
        values.insert(rest[..end].to_string());
        rest = &rest[end + 1..];
    }
    values
}

fn verifier_diff_kernel_feature_default_lane_keys(source: &str, lane: &str) -> BTreeSet<String> {
    let body = source
        .split_once("def kernel-feature-default-test-lane [feature] {")
        .expect("expected kernel-feature-default-test-lane function")
        .1
        .split_once("\ndef fixture-default-test-lane")
        .expect("expected fixture-default-test-lane to follow kernel-feature-default-test-lane")
        .0;
    let needle = format!("return \"{lane}\"");
    let mut search_start = 0;

    while let Some(relative_return) = body[search_start..].find(&needle) {
        let return_index = search_start + relative_return;
        let before_return = &body[..return_index];
        if let Some(list_start) = before_return.rfind("if $key in [") {
            let list_with_return = &body[list_start..return_index];
            return verifier_diff_quoted_strings(list_with_return);
        }
        search_start = return_index + needle.len();
    }

    panic!("expected kernel-feature-default-test-lane to contain a {lane} key list")
}

fn verifier_diff_program_target_expectations(source: &str) -> BTreeMap<String, BTreeSet<String>> {
    let body = verifier_diff_const_body(source, "PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS", '[');
    let mut expectations = BTreeMap::new();

    for line in body.lines() {
        let Some(target) = verifier_diff_quoted_field(line, "target") else {
            continue;
        };
        let feature_list = line
            .split_once("feature_keys: [")
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(list, _)| list)
            .unwrap_or_else(|| {
                panic!("PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS target {target} missing feature_keys")
            });
        let feature_keys = verifier_diff_quoted_strings(feature_list);
        assert!(
            expectations
                .insert(target.to_string(), feature_keys)
                .is_none(),
            "duplicate PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS target {target}"
        );
    }

    expectations
}

fn program_compatibility_verifier_feature_key(
    requirement: ProgramCompatibilityRequirement,
) -> Option<&'static str> {
    Some(match requirement {
        ProgramCompatibilityRequirement::SocketFilterProgram => {
            "program:BPF_PROG_TYPE_SOCKET_FILTER"
        }
        ProgramCompatibilityRequirement::KprobeProgram => "program:BPF_PROG_TYPE_KPROBE",
        ProgramCompatibilityRequirement::TracepointProgram => "program:BPF_PROG_TYPE_TRACEPOINT",
        ProgramCompatibilityRequirement::RawTracepointProgram => {
            "program:BPF_PROG_TYPE_RAW_TRACEPOINT"
        }
        ProgramCompatibilityRequirement::PerfEventProgram => "program:BPF_PROG_TYPE_PERF_EVENT",
        ProgramCompatibilityRequirement::XdpProgram => "program:BPF_PROG_TYPE_XDP",
        ProgramCompatibilityRequirement::XdpSkbAttachMode => "attach:xdp-skb",
        ProgramCompatibilityRequirement::XdpDrvAttachMode => "attach:xdp-drv",
        ProgramCompatibilityRequirement::XdpHwAttachMode => "attach:xdp-hw",
        ProgramCompatibilityRequirement::XdpDevmapAttach => "attach:BPF_XDP_DEVMAP",
        ProgramCompatibilityRequirement::XdpCpumapAttach => "attach:BPF_XDP_CPUMAP",
        ProgramCompatibilityRequirement::TcProgram => "program:BPF_PROG_TYPE_SCHED_CLS",
        ProgramCompatibilityRequirement::SkLookupProgram => "program:BPF_PROG_TYPE_SK_LOOKUP",
        ProgramCompatibilityRequirement::TracingProgram => "program:BPF_PROG_TYPE_TRACING",
        ProgramCompatibilityRequirement::LsmProgram => "program:BPF_PROG_TYPE_LSM",
        ProgramCompatibilityRequirement::KernelBtf => "kernel:btf-vmlinux",
        ProgramCompatibilityRequirement::BpfTrampoline => "program:bpf-trampoline",
        ProgramCompatibilityRequirement::SleepableProgram => "section:sleepable-program",
        ProgramCompatibilityRequirement::KprobeMulti => "attach:BPF_TRACE_KPROBE_MULTI",
        ProgramCompatibilityRequirement::UprobeMulti => "attach:BPF_TRACE_UPROBE_MULTI",
        ProgramCompatibilityRequirement::RawTracepointWritable => "section:raw_tracepoint.w",
        ProgramCompatibilityRequirement::CgroupLsm => "attach:BPF_LSM_CGROUP",
        ProgramCompatibilityRequirement::ExtensionProgram => "program:BPF_PROG_TYPE_EXT",
        ProgramCompatibilityRequirement::SyscallProgram => "program:BPF_PROG_TYPE_SYSCALL",
        ProgramCompatibilityRequirement::BpfIterator => "program:BPF_PROG_TYPE_TRACING-iter",
        ProgramCompatibilityRequirement::BpfIteratorTaskTarget => "iter-target:task",
        ProgramCompatibilityRequirement::BpfIteratorTaskFileTarget => "iter-target:task_file",
        ProgramCompatibilityRequirement::BpfIteratorTaskVmaTarget => "iter-target:task_vma",
        ProgramCompatibilityRequirement::BpfIteratorBpfMapTarget => "iter-target:bpf_map",
        ProgramCompatibilityRequirement::BpfIteratorCgroupTarget => "iter-target:cgroup",
        ProgramCompatibilityRequirement::BpfIteratorBpfMapElemTarget => "iter-target:bpf_map_elem",
        ProgramCompatibilityRequirement::BpfIteratorBpfSkStorageMapTarget => {
            "iter-target:bpf_sk_storage_map"
        }
        ProgramCompatibilityRequirement::BpfIteratorSockmapTarget => "iter-target:sockmap",
        ProgramCompatibilityRequirement::BpfIteratorBpfProgTarget => "iter-target:bpf_prog",
        ProgramCompatibilityRequirement::BpfIteratorBpfLinkTarget => "iter-target:bpf_link",
        ProgramCompatibilityRequirement::BpfIteratorTcpTarget => "iter-target:tcp",
        ProgramCompatibilityRequirement::BpfIteratorUdpTarget => "iter-target:udp",
        ProgramCompatibilityRequirement::BpfIteratorUnixTarget => "iter-target:unix",
        ProgramCompatibilityRequirement::BpfIteratorIpv6RouteTarget => "iter-target:ipv6_route",
        ProgramCompatibilityRequirement::BpfIteratorKsymTarget => "iter-target:ksym",
        ProgramCompatibilityRequirement::BpfIteratorNetlinkTarget => "iter-target:netlink",
        ProgramCompatibilityRequirement::BpfIteratorKmemCacheTarget => "iter-target:kmem_cache",
        ProgramCompatibilityRequirement::BpfIteratorDmabufTarget => "iter-target:dmabuf",
        ProgramCompatibilityRequirement::XdpMultiBuffer => "section:xdp.frags",
        ProgramCompatibilityRequirement::FlowDissector => "program:BPF_PROG_TYPE_FLOW_DISSECTOR",
        ProgramCompatibilityRequirement::Tcx => "attach:tcx",
        ProgramCompatibilityRequirement::Netkit => "attach:netkit",
        ProgramCompatibilityRequirement::NetfilterLink => "attach:netfilter-link",
        ProgramCompatibilityRequirement::NetfilterDefrag => "attach:netfilter-defrag",
        ProgramCompatibilityRequirement::RouteLwt => "program:BPF_PROG_TYPE_LWT",
        ProgramCompatibilityRequirement::RouteLwtSeg6Local => "program:BPF_PROG_TYPE_LWT_SEG6LOCAL",
        ProgramCompatibilityRequirement::SockMapAttach => return None,
        ProgramCompatibilityRequirement::SkMsgSockMapAttach => "program:BPF_PROG_TYPE_SK_MSG",
        ProgramCompatibilityRequirement::SkSkbSockMapAttach => "program:BPF_PROG_TYPE_SK_SKB",
        ProgramCompatibilityRequirement::SkReuseportAttach => "attach:BPF_SK_REUSEPORT_SELECT",
        ProgramCompatibilityRequirement::SkReuseportMigration => {
            "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"
        }
        ProgramCompatibilityRequirement::TcActionProgram => "program:BPF_PROG_TYPE_SCHED_ACT",
        ProgramCompatibilityRequirement::CgroupSkbProgram => "program:BPF_PROG_TYPE_CGROUP_SKB",
        ProgramCompatibilityRequirement::CgroupSockProgram => "program:BPF_PROG_TYPE_CGROUP_SOCK",
        ProgramCompatibilityRequirement::CgroupDeviceProgram => {
            "program:BPF_PROG_TYPE_CGROUP_DEVICE"
        }
        ProgramCompatibilityRequirement::CgroupSockAddrProgram => {
            "program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"
        }
        ProgramCompatibilityRequirement::CgroupSysctlProgram => {
            "program:BPF_PROG_TYPE_CGROUP_SYSCTL"
        }
        ProgramCompatibilityRequirement::CgroupSockoptProgram => {
            "program:BPF_PROG_TYPE_CGROUP_SOCKOPT"
        }
        ProgramCompatibilityRequirement::SockOpsProgram => "program:BPF_PROG_TYPE_SOCK_OPS",
        ProgramCompatibilityRequirement::CgroupV2 => return None,
        ProgramCompatibilityRequirement::LircMode2 => "program:BPF_PROG_TYPE_LIRC_MODE2",
        ProgramCompatibilityRequirement::StructOps => "program:BPF_PROG_TYPE_STRUCT_OPS",
        ProgramCompatibilityRequirement::TcpCongestionOps => "struct_ops:tcp_congestion_ops",
        ProgramCompatibilityRequirement::HidBpfOps => "struct_ops:hid_bpf_ops",
        ProgramCompatibilityRequirement::SchedExt => "struct_ops:sched_ext_ops",
        ProgramCompatibilityRequirement::QdiscOps => "struct_ops:Qdisc_ops",
        ProgramCompatibilityRequirement::CgroupUnixSockAddr => "attach:BPF_CGROUP_UNIX_SOCK_ADDR",
    })
}

#[test]
fn test_verifier_diff_iter_target_feature_table_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let records =
        verifier_diff_feature_table_records(verifier_diff, "ITER_TARGET_KERNEL_FEATURES", "target");
    let mut expected_targets = BTreeSet::new();

    for target_kind in IterTargetKind::all() {
        let target = target_kind.key();
        expected_targets.insert(target.to_string());
        let spec = ProgramSpec::parse(&format!("iter:{target}"))
            .unwrap_or_else(|err| panic!("iter:{target} should parse: {err}"));
        let requirement = spec
            .compatibility_requirements()
            .into_iter()
            .find(|requirement| {
                program_compatibility_verifier_feature_key(*requirement)
                    .is_some_and(|key| key.starts_with("iter-target:"))
            })
            .unwrap_or_else(|| panic!("iter:{target} should have a target requirement"));
        let expected_feature_key = program_compatibility_verifier_feature_key(requirement)
            .unwrap_or_else(|| panic!("{requirement:?} should have verifier feature metadata"));
        let record = records
            .get(target)
            .unwrap_or_else(|| panic!("ITER_TARGET_KERNEL_FEATURES missing iter target {target}"));

        assert_eq!(
            record.key, expected_feature_key,
            "ITER_TARGET_KERNEL_FEATURES key drifted for iter:{target}"
        );
        assert_eq!(
            Some(record.min_kernel.as_str()),
            requirement.minimum_kernel(),
            "ITER_TARGET_KERNEL_FEATURES minimum kernel drifted for iter:{target}"
        );
        assert_eq!(
            Some(record.source.as_str()),
            requirement.minimum_kernel_source(),
            "ITER_TARGET_KERNEL_FEATURES source drifted for iter:{target}"
        );
        assert_eq!(
            record.max_kernel_exclusive, None,
            "iterator target features should not use max_kernel_exclusive"
        );
    }

    assert_eq!(
        records.keys().cloned().collect::<BTreeSet<_>>(),
        expected_targets,
        "ITER_TARGET_KERNEL_FEATURES should exactly cover modeled iterator targets"
    );
}

fn assert_verifier_feature_record_matches_map_kind(
    kind: MapKind,
    record: &VerifierDiffFeatureRecord,
) {
    let requirement = kind.compatibility_requirement();
    assert_eq!(
        record.key,
        requirement.key(),
        "scripts/verifier_diff.nu map feature key drifted for {}",
        kind.key()
    );
    assert_eq!(
        record.min_kernel,
        requirement.minimum_kernel(),
        "scripts/verifier_diff.nu map min_kernel drifted for {}",
        kind.key()
    );
    assert_eq!(
        record.source,
        requirement.minimum_kernel_source(),
        "scripts/verifier_diff.nu map source drifted for {}",
        kind.key()
    );
    assert_eq!(
        record.max_kernel_exclusive, None,
        "map compatibility features should not use max_kernel_exclusive"
    );
}

#[test]
fn test_verifier_diff_map_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let records =
        verifier_diff_feature_table_records(verifier_diff, "MAP_KIND_KERNEL_FEATURES", "kind");

    for kind in MapKind::all() {
        let record = records.get(kind.key()).unwrap_or_else(|| {
            panic!(
                "scripts/verifier_diff.nu MAP_KIND_KERNEL_FEATURES is missing {}",
                kind.key()
            )
        });
        assert_verifier_feature_record_matches_map_kind(*kind, record);
    }

    for (kind_name, record) in &records {
        let kind = MapKind::from_name(kind_name).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu has unknown map kind feature entry {kind_name}")
        });
        assert_verifier_feature_record_matches_map_kind(kind, record);
    }
}

fn verifier_diff_map_value_token(requirement: MapValueCompatibilityRequirement) -> &'static str {
    match requirement {
        MapValueCompatibilityRequirement::BpfSpinLock => "bpf_spin_lock",
        MapValueCompatibilityRequirement::BpfTimer => "bpf_timer",
        MapValueCompatibilityRequirement::BpfKptr => "kptr:",
        MapValueCompatibilityRequirement::BpfWorkqueue => "bpf_wq",
        MapValueCompatibilityRequirement::BpfRefcount => "bpf_refcount",
        MapValueCompatibilityRequirement::BpfListHead => "bpf_list_head",
        MapValueCompatibilityRequirement::BpfListNode => "bpf_list_node",
        MapValueCompatibilityRequirement::BpfRbRoot => "bpf_rb_root",
        MapValueCompatibilityRequirement::BpfRbNode => "bpf_rb_node",
    }
}

fn assert_verifier_feature_record_matches_map_value(
    requirement: MapValueCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) {
    assert_eq!(
        record.key,
        requirement.key(),
        "scripts/verifier_diff.nu map-value feature key drifted for {}",
        requirement.key()
    );
    assert_eq!(
        record.min_kernel,
        requirement.minimum_kernel(),
        "scripts/verifier_diff.nu map-value min_kernel drifted for {}",
        requirement.key()
    );
    assert_eq!(
        record.source,
        requirement.minimum_kernel_source(),
        "scripts/verifier_diff.nu map-value source drifted for {}",
        requirement.key()
    );
    assert_eq!(
        record.max_kernel_exclusive, None,
        "map-value compatibility features should not use max_kernel_exclusive"
    );
}

fn assert_verifier_feature_record_matches_context_requirement(
    label: &str,
    requirement: &ContextFieldCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) {
    assert_eq!(
        record.key,
        requirement.key(),
        "scripts/verifier_diff.nu context-field feature key drifted for {label}"
    );
    assert_eq!(
        record.min_kernel,
        requirement.minimum_kernel(),
        "scripts/verifier_diff.nu context-field min_kernel drifted for {label}"
    );
    assert_eq!(
        record.source,
        requirement.minimum_kernel_source(),
        "scripts/verifier_diff.nu context-field source drifted for {label}"
    );
    assert_eq!(
        record.max_kernel_exclusive, None,
        "context-field compatibility features should not use max_kernel_exclusive"
    );
}

fn assert_verifier_feature_record_matches_kfunc_requirement(
    name: &str,
    requirement: KfuncCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) {
    assert_eq!(
        record.key,
        requirement.key(),
        "scripts/verifier_diff.nu kfunc feature key drifted for {name}"
    );
    assert_eq!(
        record.min_kernel,
        requirement.minimum_kernel(),
        "scripts/verifier_diff.nu kfunc min_kernel drifted for {name}"
    );
    assert_eq!(
        record.source,
        requirement.minimum_kernel_source(),
        "scripts/verifier_diff.nu kfunc source drifted for {name}"
    );
    assert_eq!(
        record.max_kernel_exclusive.as_deref(),
        requirement.maximum_kernel_exclusive(),
        "scripts/verifier_diff.nu kfunc max_kernel_exclusive drifted for {name}"
    );
    assert_eq!(
        record.max_kernel_exclusive_source.as_deref(),
        requirement.maximum_kernel_exclusive_source(),
        "scripts/verifier_diff.nu kfunc max_kernel_exclusive_source drifted for {name}"
    );
}

fn verifier_feature_record_matches_context_requirement(
    requirement: &ContextFieldCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) -> bool {
    record.key == requirement.key()
        && record.min_kernel == requirement.minimum_kernel()
        && record.source == requirement.minimum_kernel_source()
        && record.max_kernel_exclusive.is_none()
}

fn all_modeled_tracepoint_payload_scanner_checks() -> Vec<(String, String)> {
    let mut checks = BTreeSet::new();

    for &syscall in TracepointContext::well_known_sys_enter_syscalls() {
        let enter_name = format!("sys_enter_{syscall}");
        let enter_target = format!("tracepoint:syscalls/{enter_name}");
        for field in TracepointContext::sys_enter(&enter_name).fields {
            checks.insert((enter_target.clone(), field.name));
        }

        let exit_name = format!("sys_exit_{syscall}");
        let exit_target = format!("tracepoint:syscalls/{exit_name}");
        for field in TracepointContext::sys_exit(&exit_name).fields {
            checks.insert((exit_target.clone(), field.name));
        }
    }

    checks.into_iter().collect()
}

fn verifier_diff_nu_field_target_feature_records(
    function_name: &str,
    checks: &[(String, String)],
) -> Option<Vec<VerifierDiffFeatureRecord>> {
    let check_rows = checks
        .iter()
        .map(|(target, field)| format!("    {{ target: {:?} field: {:?} }}", target, field))
        .collect::<Vec<_>>()
        .join("\n");
    let script = format!(
        r#"source scripts/verifier_diff.nu
let checks = [
{check_rows}
]
$checks
| enumerate
| each {{|row|
    let check = $row.item
    let feature = ({function_name} $check.field $check.target)
    {{
        index: $row.index
        key: ($feature | get -o key)
        min_kernel: ($feature | get -o min_kernel)
        source: ($feature | get -o source)
        max_kernel_exclusive: ($feature | get -o max_kernel_exclusive)
        max_kernel_exclusive_source: ($feature | get -o max_kernel_exclusive_source)
    }}
}}
| to json"#
    );

    let output = run_nu_script(&script, &format!("{function_name} scanner coverage"))?;
    assert!(
        output.status.success(),
        "verifier_diff.nu {function_name} scanner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("verifier_diff.nu scanner should emit JSON");
    let actual = actual
        .as_array()
        .expect("verifier_diff.nu scanner output should be a JSON list");
    assert_eq!(
        actual.len(),
        checks.len(),
        "verifier_diff.nu scanner should return one result per checked field"
    );

    let mut records = Vec::new();
    for value in actual {
        let index = value
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .expect("verifier_diff.nu scanner result should include index")
            as usize;
        assert!(
            index < checks.len(),
            "verifier_diff.nu scanner index should refer to a checked field"
        );
        records.push(VerifierDiffFeatureRecord {
            key: value
                .get("key")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            min_kernel: value
                .get("min_kernel")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            source: value
                .get("source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            max_kernel_exclusive: value
                .get("max_kernel_exclusive")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            max_kernel_exclusive_source: value
                .get("max_kernel_exclusive_source")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        });
    }

    Some(records)
}

fn verifier_diff_nu_target_feature_keys(targets: &[String]) -> Option<Vec<BTreeSet<String>>> {
    let target_rows = targets
        .iter()
        .map(|target| format!("    {target:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    let script = format!(
        r#"source scripts/verifier_diff.nu
let targets = [
{target_rows}
]
$targets
| enumerate
| each {{|row|
    {{
        index: $row.index
        keys: (
            target-kernel-features $row.item
            | each {{|feature| $feature.key }}
            | sort
        )
    }}
}}
| to json"#
    );

    let output = run_nu_script(&script, "target-kernel-features coverage")?;
    assert_verifier_diff_nu_success(&output, "target-kernel-features");

    Some(verifier_diff_nu_indexed_feature_keys(
        &output.stdout,
        "target-kernel-features",
        targets.len(),
        "target",
    ))
}

fn verifier_diff_nu_program_feature_keys(
    function_name: &str,
    label: &str,
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    let check_rows = checks
        .iter()
        .map(|(target, program)| format!("    {{ target: {:?} program: {:?} }}", target, program))
        .collect::<Vec<_>>()
        .join("\n");
    let script = format!(
        r#"source scripts/verifier_diff.nu
let checks = [
{check_rows}
]
$checks
| enumerate
| each {{|row|
    let check = $row.item
    {{
        index: $row.index
        keys: (
            {function_name} $check.program $check.target
            | each {{|feature| $feature.key }}
            | sort
        )
    }}
}}
| to json"#
    );

    let output = run_nu_script(&script, label)?;
    assert_verifier_diff_nu_success(&output, function_name);

    Some(verifier_diff_nu_indexed_feature_keys(
        &output.stdout,
        function_name,
        checks.len(),
        "checked program",
    ))
}

fn verifier_diff_nu_program_only_feature_keys(
    function_name: &str,
    label: &str,
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    let program_rows = programs
        .iter()
        .map(|program| format!("    {program:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    let script = format!(
        r#"source scripts/verifier_diff.nu
let programs = [
{program_rows}
]
$programs
| enumerate
| each {{|row|
    {{
        index: $row.index
        keys: (
            {function_name} $row.item
            | each {{|feature| $feature.key }}
            | sort
        )
    }}
}}
| to json"#
    );

    let output = run_nu_script(&script, label)?;
    assert_verifier_diff_nu_success(&output, function_name);

    Some(verifier_diff_nu_indexed_feature_keys(
        &output.stdout,
        function_name,
        programs.len(),
        "checked program",
    ))
}

fn assert_verifier_diff_nu_success(output: &Output, function_name: &str) {
    assert!(
        output.status.success(),
        "verifier_diff.nu {function_name} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verifier_diff_nu_indexed_feature_keys(
    stdout: &[u8],
    function_name: &str,
    expected_len: usize,
    subject: &str,
) -> Vec<BTreeSet<String>> {
    let actual: serde_json::Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|_| panic!("verifier_diff.nu {function_name} should emit JSON"));
    let actual = actual
        .as_array()
        .unwrap_or_else(|| panic!("verifier_diff.nu {function_name} output should be a JSON list"));
    assert_eq!(
        actual.len(),
        expected_len,
        "verifier_diff.nu {function_name} should return one result per {subject}"
    );

    let mut keys_by_index = vec![BTreeSet::new(); expected_len];
    for value in actual {
        let index = value
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| {
                panic!("verifier_diff.nu {function_name} result should include index")
            }) as usize;
        assert!(
            index < expected_len,
            "verifier_diff.nu {function_name} index should refer to a {subject}"
        );
        let keys = value
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| {
                panic!("verifier_diff.nu {function_name} result should include keys")
            });
        keys_by_index[index] = keys
            .iter()
            .map(|key| {
                key.as_str()
                    .unwrap_or_else(|| {
                        panic!("verifier_diff.nu {function_name} keys should be strings")
                    })
                    .to_string()
            })
            .collect();
    }

    keys_by_index
}

fn verifier_diff_nu_program_map_feature_keys(programs: &[String]) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-map-kernel-features",
        "program-map-kernel-features coverage",
        programs,
    )
}

fn verifier_diff_nu_program_reserved_map_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-reserved-map-kernel-features",
        "program-reserved-map-kernel-features coverage",
        programs,
    )
}

fn verifier_diff_nu_program_language_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-language-kernel-features",
        "program-language-kernel-features coverage",
        programs,
    )
}

fn verifier_diff_nu_program_map_value_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-map-value-kernel-features",
        "program-map-value-kernel-features coverage",
        programs,
    )
}

fn verifier_diff_nu_program_global_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-global-kernel-features",
        "program-global-kernel-features coverage",
        programs,
    )
}

fn verifier_diff_nu_program_helper_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-helper-kernel-features",
        "program-helper-kernel-features coverage",
        programs,
    )
}

fn verifier_diff_nu_program_context_field_feature_keys(
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_feature_keys(
        "program-context-field-kernel-features",
        "program-context-field-kernel-features write coverage",
        checks,
    )
}

fn verifier_diff_nu_program_kfunc_feature_keys(
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_feature_keys(
        "program-kfunc-kernel-features",
        "program-kfunc-kernel-features write coverage",
        checks,
    )
}

fn verifier_diff_nu_program_struct_ops_feature_keys(
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_feature_keys(
        "program-struct-ops-kernel-features",
        "program-struct-ops-kernel-features coverage",
        checks,
    )
}

fn verifier_diff_nu_program_surface_feature_keys(
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_feature_keys(
        "program-surface-kernel-features",
        "program-surface-kernel-features write coverage",
        checks,
    )
}

fn helper_feature_keys(helpers: impl IntoIterator<Item = BpfHelper>) -> BTreeSet<String> {
    helpers
        .into_iter()
        .map(|helper| {
            HelperCompatibilityRequirement::for_helper(helper)
                .unwrap_or_else(|| {
                    panic!(
                        "{} should carry helper compatibility metadata",
                        helper.name()
                    )
                })
                .key()
        })
        .collect()
}

fn map_kind_feature_keys(kinds: impl IntoIterator<Item = MapKind>) -> BTreeSet<String> {
    kinds
        .into_iter()
        .map(|kind| kind.compatibility_requirement().key().to_string())
        .collect()
}

fn map_value_feature_keys(
    requirements: impl IntoIterator<Item = MapValueCompatibilityRequirement>,
) -> BTreeSet<String> {
    requirements
        .into_iter()
        .map(|requirement| requirement.key().to_string())
        .collect()
}

fn compiled_feature_keys(
    requirements: impl IntoIterator<Item = CompiledFeatureCompatibilityRequirement>,
) -> BTreeSet<String> {
    requirements
        .into_iter()
        .map(|requirement| requirement.key().to_string())
        .collect()
}

fn global_feature_keys(
    requirements: impl IntoIterator<Item = GlobalCompatibilityRequirement>,
) -> BTreeSet<String> {
    requirements
        .into_iter()
        .map(|requirement| requirement.key().to_string())
        .collect()
}

fn program_feature_keys(
    requirements: impl IntoIterator<Item = ProgramCompatibilityRequirement>,
) -> BTreeSet<String> {
    requirements
        .into_iter()
        .filter_map(program_compatibility_verifier_feature_key)
        .map(str::to_string)
        .collect()
}

fn kfunc_feature_keys_for_target<'a>(
    target: &str,
    kfuncs: impl IntoIterator<Item = &'a str>,
) -> BTreeSet<String> {
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative kfunc target {target} should parse: {err}"));
    kfuncs
        .into_iter()
        .map(|kfunc| {
            spec.kfunc_compatibility_requirement_for_name(kfunc)
                .unwrap_or_else(|| {
                    panic!(
                        "representative kfunc target {target} should expose metadata for {kfunc}"
                    )
                })
                .key()
        })
        .collect()
}

fn verifier_diff_nu_program_kfunc_feature_records(
    checks: &[(String, String)],
) -> Option<Vec<VerifierDiffFeatureRecord>> {
    let check_rows = checks
        .iter()
        .map(|(target, kfunc)| format!("    {{ target: {:?} kfunc: {:?} }}", target, kfunc))
        .collect::<Vec<_>>()
        .join("\n");
    let script = format!(
        r#"source scripts/verifier_diff.nu
let checks = [
{check_rows}
]
$checks
| enumerate
| each {{|row|
    let check = $row.item
    let program = ([
        "{{|ctx|"
        $"  kfunc-call \"($check.kfunc)\""
        "  0"
        "}}"
    ] | str join "\n")
    let matches = (
        program-kfunc-kernel-features $program $check.target
        | where {{|feature| $feature.key == $"kfunc:($check.kfunc)" }}
    )
    let feature = if ($matches | is-empty) {{ null }} else {{ $matches | first }}
    {{
        index: $row.index
        key: ($feature | get -o key)
        min_kernel: ($feature | get -o min_kernel)
        source: ($feature | get -o source)
        max_kernel_exclusive: ($feature | get -o max_kernel_exclusive)
    }}
}}
| to json"#
    );

    let output = run_nu_script(&script, "program-kfunc-kernel-features coverage")?;
    assert!(
        output.status.success(),
        "verifier_diff.nu program-kfunc-kernel-features failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("verifier_diff.nu program-kfunc-kernel-features should emit JSON");
    let actual = actual
        .as_array()
        .expect("verifier_diff.nu program-kfunc-kernel-features output should be a JSON list");
    assert_eq!(
        actual.len(),
        checks.len(),
        "verifier_diff.nu program-kfunc-kernel-features should return one result per checked target"
    );

    let mut records = vec![
        VerifierDiffFeatureRecord {
            key: String::new(),
            min_kernel: String::new(),
            source: String::new(),
            max_kernel_exclusive: None,
            max_kernel_exclusive_source: None,
        };
        checks.len()
    ];
    for value in actual {
        let index = value
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .expect("verifier_diff.nu program kfunc result should include index")
            as usize;
        assert!(
            index < checks.len(),
            "verifier_diff.nu program kfunc index should refer to a checked target"
        );
        records[index] = VerifierDiffFeatureRecord {
            key: value
                .get("key")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            min_kernel: value
                .get("min_kernel")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            source: value
                .get("source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            max_kernel_exclusive: value
                .get("max_kernel_exclusive")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            max_kernel_exclusive_source: value
                .get("max_kernel_exclusive_source")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        };
    }

    Some(records)
}

#[test]
fn test_verifier_diff_map_value_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let records =
        verifier_diff_feature_table_records(verifier_diff, "MAP_VALUE_KERNEL_FEATURES", "token");
    let mut expected_tokens = BTreeSet::new();

    for requirement in MapValueCompatibilityRequirement::all() {
        let token = verifier_diff_map_value_token(*requirement);
        assert!(
            expected_tokens.insert(token),
            "duplicate verifier_diff.nu map-value token mapping for {requirement:?}"
        );
        let record = records.get(token).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu MAP_VALUE_KERNEL_FEATURES is missing {token}")
        });
        assert_verifier_feature_record_matches_map_value(*requirement, record);
    }

    let unexpected_tokens = records
        .keys()
        .filter(|token| !expected_tokens.contains(token.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        unexpected_tokens.is_empty(),
        "scripts/verifier_diff.nu has map-value feature metadata without a Rust requirement: {unexpected_tokens:?}"
    );
}

mod context_field_metadata_tests;
mod context_read_scanner_tests;
mod context_write_scanner_tests;
mod metadata_tests;
mod program_feature_scanner_tests;
mod program_surface_scanner_tests;
mod runtime_tests;
mod source_tests;
