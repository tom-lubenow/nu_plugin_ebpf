use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use crate::compiler::mir::CtxField;
use crate::compiler::{
    CompiledFeatureCompatibilityRequirement, ContextFieldCompatibilityRequirement, EbpfProgramType,
    MapKind, MapValueCompatibilityRequirement, ProgramCompatibilityRequirement,
};
use crate::program_spec::{IterTargetKind, ProgramSpec};

const REPRESENTATIVE_CONTEXT_FIELD_SPEC_SOURCES: &[&str] = &[
    "raw_tracepoint:sys_enter",
    "tracepoint:syscalls/sys_enter_openat",
    "fentry:security_file_open",
    "fexit:ksys_read",
    "lsm:file_open",
    "socket_filter:udp4:127.0.0.1:31337",
    "tc_action:diff-action",
    "tc:lo:ingress",
    "tcx:lo:ingress",
    "netkit:lo:primary",
    "xdp:lo",
    "sk_msg:/sys/fs/bpf/demo_sockmap",
    "sk_skb:/sys/fs/bpf/demo_sockmap",
    "sk_skb_parser:/sys/fs/bpf/demo_sockmap",
    "sk_lookup:/proc/self/ns/net",
    "sk_reuseport:migrate",
    "cgroup_skb:/sys/fs/cgroup:egress",
    "cgroup_sock:/sys/fs/cgroup:sock_create",
    "cgroup_sock_addr:/sys/fs/cgroup:connect4",
    "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
    "cgroup_sockopt:/sys/fs/cgroup:get",
    "cgroup_sockopt:/sys/fs/cgroup:set",
    "cgroup_sysctl:/sys/fs/cgroup",
    "cgroup_device:/sys/fs/cgroup",
    "sock_ops:/sys/fs/cgroup",
    "lwt_xmit:demo-route",
    "flow_dissector:/proc/self/ns/net",
    "netfilter:ipv4:pre_routing:priority=-100:defrag",
    "perf_event:software:cpu-clock:period=100000",
    "lirc_mode2:/dev/lirc0",
    "iter:task_file",
    "iter:task_vma",
    "iter:bpf_map_elem",
    "iter:bpf_sk_storage_map",
    "iter:sockmap",
    "iter:udp",
    "iter:unix",
];

#[derive(Debug, Clone)]
struct VerifierDiffFeatureRecord {
    key: String,
    min_kernel: String,
    source: String,
    max_kernel_exclusive: Option<String>,
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
    let rest = text.split_once(&needle)?.1;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn verifier_diff_dollar_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("{field}: $");
    let rest = text.split_once(&needle)?.1;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '}')
        .unwrap_or(rest.len());
    Some(&rest[..end])
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

#[test]
fn test_verifier_diff_fixture_summary_exposes_target() {
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
    let summary_body = verifier_diff
        .split_once("def fixture-summary [fixture compat_kernel] {")
        .expect("expected fixture-summary function")
        .1
        .split_once("\ndef fixture-status-count")
        .expect("expected fixture-status-count after fixture-summary")
        .0;
    assert!(
        summary_body.contains("target: (optional $fixture target \"\")"),
        "fixture-summary should expose the raw fixture target in --list --json output"
    );

    let list_body = verifier_diff
        .split_once("if $list {")
        .expect("expected list output branch")
        .1
        .split_once("\n    if $matrix {")
        .expect("expected matrix branch after list output branch")
        .0;
    assert!(
        list_body.contains("target=($summary.target)"),
        "human --list output should include the raw fixture target"
    );
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
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
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
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
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

fn verifier_feature_record_matches_context_requirement(
    requirement: &ContextFieldCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) -> bool {
    record.key == requirement.key()
        && record.min_kernel == requirement.minimum_kernel()
        && record.source == requirement.minimum_kernel_source()
        && record.max_kernel_exclusive.is_none()
}

#[test]
fn test_verifier_diff_map_value_feature_metadata_matches_rust() {
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
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

#[test]
fn test_verifier_diff_context_field_feature_metadata_matches_rust() {
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
    let records = verifier_diff_feature_table_records(
        verifier_diff,
        "CONTEXT_FIELD_KERNEL_FEATURES",
        "field",
    );

    for (field_name, record) in &records {
        let field =
            EbpfProgramType::resolve_untyped_ctx_field_name(field_name).unwrap_or_else(|err| {
                panic!("scripts/verifier_diff.nu context field {field_name} should resolve: {err}")
            });
        assert!(
            !matches!(field, CtxField::TracepointField(_)),
            "scripts/verifier_diff.nu context field {field_name} resolved as an unversioned tracepoint payload field"
        );
        let requirement = ContextFieldCompatibilityRequirement::for_field(&field).unwrap_or_else(|| {
            panic!(
                "scripts/verifier_diff.nu context field {field_name} ({}) has no Rust compatibility requirement",
                field.display_name()
            )
        });

        assert_verifier_feature_record_matches_context_requirement(
            field_name,
            &requirement,
            record,
        );
    }

    assert!(
        !records.is_empty(),
        "expected verifier_diff.nu context-field feature metadata"
    );
}

#[test]
fn test_verifier_diff_context_field_feature_metadata_covers_representative_rust_fields() {
    #[derive(Clone)]
    struct ExpectedContextFieldFeature {
        target: String,
        field: String,
        requirement: ContextFieldCompatibilityRequirement,
    }

    let mut expected = Vec::new();

    for spec_text in REPRESENTATIVE_CONTEXT_FIELD_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text).unwrap_or_else(|err| {
            panic!("representative context field target {spec_text} should parse: {err}")
        });
        let mut seen_requirement_keys = BTreeSet::new();

        for entry in spec.program_type().ctx_field_name_entries() {
            if spec.ctx_field_access_error(&entry.field).is_some() {
                continue;
            }
            let Some(requirement) = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
                &entry.field,
                &spec,
            ) else {
                continue;
            };
            let requirement_key = requirement.key();
            if !seen_requirement_keys.insert(requirement_key.clone()) {
                continue;
            }

            expected.push(ExpectedContextFieldFeature {
                target: (*spec_text).to_string(),
                field: entry.name.to_string(),
                requirement,
            });
        }
    }

    let check_rows = expected
        .iter()
        .map(|check| {
            format!(
                "    {{ target: {:?} field: {:?} }}",
                check.target, check.field
            )
        })
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
    let feature = (context-field-kernel-feature $check.field $check.target)
    {{
        index: $row.index
        target: $check.target
        field: $check.field
        key: ($feature | get -o key)
        min_kernel: ($feature | get -o min_kernel)
        source: ($feature | get -o source)
        max_kernel_exclusive: ($feature | get -o max_kernel_exclusive)
    }}
}}
| to json"#
    );

    let output = match Command::new("nu")
        .arg("-c")
        .arg(script)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "skipping verifier_diff.nu context scanner coverage: nu binary was not found"
            );
            return;
        }
        Err(err) => panic!("failed to run nu for verifier_diff.nu context scanner: {err}"),
    };
    assert!(
        output.status.success(),
        "verifier_diff.nu context scanner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("verifier_diff.nu context scanner should emit JSON");
    let actual = actual
        .as_array()
        .expect("verifier_diff.nu context scanner output should be a JSON list");
    assert_eq!(
        actual.len(),
        expected.len(),
        "verifier_diff.nu context scanner should return one result per checked field"
    );

    let mut mismatches = Vec::new();
    for value in actual {
        let index = value
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .expect("verifier_diff.nu context scanner result should include index")
            as usize;
        let check = expected
            .get(index)
            .expect("verifier_diff.nu context scanner index should refer to a checked field");
        let record = VerifierDiffFeatureRecord {
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
        };
        if !verifier_feature_record_matches_context_requirement(&check.requirement, &record) {
            mismatches.push(format!(
                "{} ctx.{} expected key={} min_kernel={} source={} actual key={} min_kernel={} source={}",
                check.target,
                check.field,
                check.requirement.key(),
                check.requirement.minimum_kernel(),
                check.requirement.minimum_kernel_source(),
                record.key,
                record.min_kernel,
                record.source
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu context-field scanner drifted from Rust metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_target_context_field_feature_metadata_matches_rust() {
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
    let records = verifier_diff_target_context_field_feature_records(verifier_diff);

    for record in &records {
        let spec = ProgramSpec::parse(&record.target).unwrap_or_else(|err| {
            panic!(
                "verifier_diff.nu target context expectation target {} should parse: {err}",
                record.target
            )
        });
        let field = spec
            .resolve_ctx_field_name(&record.field)
            .unwrap_or_else(|err| {
                panic!(
                    "verifier_diff.nu target context expectation {} ctx.{} should resolve: {err}",
                    record.target, record.field
                )
            });
        let target = if spec.program_type() == EbpfProgramType::Iter {
            record.target.strip_prefix("iter:")
        } else {
            None
        };
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program_target(
            &field,
            Some(spec.program_type()),
            target,
        )
        .unwrap_or_else(|| {
            panic!(
                "verifier_diff.nu target context expectation {} ctx.{} ({}) has no Rust compatibility requirement",
                record.target,
                record.field,
                field.display_name()
            )
        });

        assert_verifier_feature_record_matches_context_requirement(
            &format!("{} ctx.{}", record.target, record.field),
            &requirement,
            &record.feature,
        );
    }

    assert!(
        !records.is_empty(),
        "expected verifier_diff.nu target-aware context-field feature metadata"
    );
}

#[test]
fn test_verifier_diff_tracepoint_field_feature_metadata_matches_rust() {
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
    let records = verifier_diff_tracepoint_field_feature_records(verifier_diff);

    for record in &records {
        let spec = ProgramSpec::parse(&record.target).unwrap_or_else(|err| {
            panic!(
                "verifier_diff.nu tracepoint field target {} should parse: {err}",
                record.target
            )
        });
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
            &CtxField::TracepointField(record.field.clone()),
            &spec,
        )
        .unwrap_or_else(|| {
            panic!(
                "verifier_diff.nu tracepoint field expectation {} ctx.{} has no Rust compatibility requirement",
                record.target, record.field
            )
        });

        assert_verifier_feature_record_matches_context_requirement(
            &format!("{} ctx.{}", record.target, record.field),
            &requirement,
            &record.feature,
        );
    }

    assert!(
        !records.is_empty(),
        "expected verifier_diff.nu tracepoint-field feature metadata"
    );
}

#[test]
fn test_verifier_diff_program_feature_metadata_matches_rust() {
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
    let verifier_records = verifier_diff_program_feature_records(verifier_diff);
    let vm_only_keys = verifier_diff_kernel_feature_default_lane_keys(verifier_diff, "vm-only");
    let dry_run_keys = verifier_diff_kernel_feature_default_lane_keys(verifier_diff, "dry-run");
    let host_gated_keys =
        verifier_diff_kernel_feature_default_lane_keys(verifier_diff, "host-gated");
    let mut expected_keys = BTreeSet::new();

    for requirement in ProgramCompatibilityRequirement::all() {
        let Some(verifier_key) = program_compatibility_verifier_feature_key(*requirement) else {
            assert!(
                requirement.minimum_kernel().is_none(),
                "{requirement:?} has a kernel floor and needs verifier_diff.nu feature metadata"
            );
            continue;
        };
        assert!(
            expected_keys.insert(verifier_key),
            "duplicate verifier feature key mapping for {requirement:?}"
        );
        let record = verifier_records.get(verifier_key).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu is missing program feature {verifier_key}")
        });
        assert_eq!(
            Some(record.min_kernel.as_str()),
            requirement.minimum_kernel(),
            "scripts/verifier_diff.nu min_kernel drifted for {requirement:?}"
        );
        assert_eq!(
            Some(record.source.as_str()),
            requirement.minimum_kernel_source(),
            "scripts/verifier_diff.nu source drifted for {requirement:?}"
        );
        assert_eq!(
            record.max_kernel_exclusive, None,
            "program compatibility features should not use max_kernel_exclusive"
        );

        let verifier_lane =
            if verifier_key.starts_with("struct_ops:") || vm_only_keys.contains(verifier_key) {
                "vm-only"
            } else if dry_run_keys.contains(verifier_key) {
                "dry-run"
            } else if host_gated_keys.contains(verifier_key) {
                "host-gated"
            } else {
                "host-safe"
            };
        assert_eq!(
            verifier_lane,
            requirement.default_test_lane(),
            "scripts/verifier_diff.nu default test lane drifted for {requirement:?}"
        );
    }

    for requirement in CompiledFeatureCompatibilityRequirement::all() {
        let verifier_key = requirement.key();
        assert!(
            expected_keys.insert(verifier_key),
            "duplicate verifier feature key mapping for {requirement:?}"
        );
        let record = verifier_records.get(verifier_key).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu is missing compiled feature {verifier_key}")
        });
        assert_eq!(
            record.min_kernel.as_str(),
            requirement.minimum_kernel(),
            "scripts/verifier_diff.nu min_kernel drifted for {requirement:?}"
        );
        assert_eq!(
            record.source.as_str(),
            requirement.minimum_kernel_source(),
            "scripts/verifier_diff.nu source drifted for {requirement:?}"
        );
        assert_eq!(
            record.max_kernel_exclusive, None,
            "compiled compatibility features should not use max_kernel_exclusive"
        );

        let verifier_lane =
            if verifier_key.starts_with("struct_ops:") || vm_only_keys.contains(verifier_key) {
                "vm-only"
            } else if dry_run_keys.contains(verifier_key) {
                "dry-run"
            } else if host_gated_keys.contains(verifier_key) {
                "host-gated"
            } else {
                "host-safe"
            };
        assert_eq!(
            verifier_lane, "host-safe",
            "compiled compatibility features should not force fixture lanes by themselves"
        );
    }

    let unexpected_verifier_keys = verifier_records
        .keys()
        .filter(|key| !expected_keys.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        unexpected_verifier_keys.is_empty(),
        "scripts/verifier_diff.nu has program feature metadata without a Rust requirement: {unexpected_verifier_keys:?}"
    );
}

#[test]
fn test_verifier_diff_program_target_expectations_match_rust() {
    let verifier_diff = include_str!("../../../../scripts/verifier_diff.nu");
    let expectations = verifier_diff_program_target_expectations(verifier_diff);
    assert!(
        !expectations.is_empty(),
        "expected verifier_diff.nu program target compatibility expectations"
    );

    for (target, expected_feature_keys) in expectations {
        let spec = ProgramSpec::parse(&target)
            .unwrap_or_else(|err| panic!("verifier_diff.nu target {target} should parse: {err}"));
        let actual_feature_keys = spec
            .compatibility_requirements()
            .iter()
            .filter_map(|requirement| program_compatibility_verifier_feature_key(*requirement))
            .map(str::to_string)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            actual_feature_keys, expected_feature_keys,
            "verifier_diff.nu program target feature expectation drifted from ProgramSpec for {target}"
        );
    }
}
