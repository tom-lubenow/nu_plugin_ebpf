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

const VERIFIER_DIFF_SOURCE_WITH_FIXTURES: &str = concat!(
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
    include_str!("../../../../scripts/verifier_diff/fixtures.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0001_0062.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0063_0125.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0126_0187.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0188_0250.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0251_0312.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0313_0375.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0376_0437.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0438_0500.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0501_0562.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0563_0625.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0626_0687.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0688_0750.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0751_0812.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0813_0875.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0876_0937.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_0938_1000.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1001_1062.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1063_1125.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1126_1187.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1188_1250.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1251_1281.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1282_1312.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1313_1344.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1345_1375.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1376_1437.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1438_1500.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1501_1562.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1563_1625.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1626_1687.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1688_1750.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1751_1812.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1813_1875.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1876_1937.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_1938_2000.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2001_2062.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2063_2125.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2126_2187.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2188_2250.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2251_2284.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2285_2285.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2286_2286.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2287_2287.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2288_2288.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2289_2289.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2290_2290.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2291_2291.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2292_2292.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2293_2293.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2294_2294.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2295_2295.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2296_2296.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2297_2297.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2298_2298.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2299_2299.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2300_2300.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2301_2301.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2302_2302.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2303_2303.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2304_2304.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2305_2305.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2306_2306.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2307_2307.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2308_2308.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2309_2309.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2310_2310.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2311_2311.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2312_2312.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2313_2313.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2314_2314.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2315_2315.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2316_2316.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2317_2317.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2318_2318.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2319_2319.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2320_2320.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2321_2321.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2322_2322.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2323_2323.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2324_2324.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2325_2325.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2326_2326.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2327_2327.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2328_2328.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2329_2329.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2330_2330.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2331_2331.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2332_2332.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2333_2333.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2334_2334.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2335_2335.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2336_2336.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2337_2337.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2338_2338.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2339_2339.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2340_2340.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2341_2341.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2342_2342.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2343_2343.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2344_2344.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2345_2345.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2346_2346.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2347_2347.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2348_2348.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2349_2349.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2350_2350.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2351_2351.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2352_2352.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2353_2353.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2354_2354.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2355_2355.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2356_2356.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2357_2357.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2358_2358.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2359_2359.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2360_2360.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2361_2361.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2362_2362.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2363_2363.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2364_2364.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2365_2365.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2366_2366.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2367_2367.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2368_2368.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2369_2369.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2370_2370.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2371_2371.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2372_2372.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2373_2373.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2374_2374.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2375_2375.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2376_2376.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2377_2377.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2378_2378.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2379_2379.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2380_2380.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2381_2381.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2382_2382.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2383_2383.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2384_2384.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2385_2385.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2386_2386.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2387_2387.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2388_2388.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2389_2389.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2390_2390.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2391_2391.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2392_2392.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2393_2393.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2394_2394.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2395_2395.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2396_2396.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2397_2397.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2398_2398.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2399_2399.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2400_2400.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2401_2401.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2402_2402.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2403_2403.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2404_2404.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2405_2405.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2406_2406.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2407_2407.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2408_2408.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2409_2409.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2410_2410.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2411_2411.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2412_2412.nu"),
    "\n",
    include_str!("../../../../scripts/verifier_diff/fixtures/fixtures_2413_2413.nu"),
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
    "cgroup_sock:/sys/fs/cgroup:post_bind6",
    "cgroup_sock_addr:/sys/fs/cgroup:connect4",
    "cgroup_sock_addr:/sys/fs/cgroup:bind6",
    "cgroup_sock_addr:/sys/fs/cgroup:getpeername4",
    "cgroup_sock_addr:/sys/fs/cgroup:getsockname6",
    "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6",
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

fn modeled_kfunc_signature_names(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter(|line| line.contains("=> Some(Self"))
        .flat_map(verifier_diff_quoted_strings)
        .filter(|name| name.starts_with("bpf_") || name.starts_with("scx_"))
        .collect()
}

fn verifier_diff_kfunc_call_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = source;
    let marker = "kfunc-call \"";

    while let Some(start) = rest.find(marker) {
        rest = &rest[start + marker.len()..];
        let Some(end) = rest.find('"') else {
            break;
        };
        names.insert(rest[..end].to_string());
        rest = &rest[end + 1..];
    }

    names
}

fn modeled_helper_names(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter(|line| line.contains("=> \"bpf_"))
        .flat_map(verifier_diff_quoted_strings)
        .filter(|name| name.starts_with("bpf_"))
        .collect()
}

fn verifier_diff_helper_call_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = source;
    let marker = "helper-call \"";

    while let Some(start) = rest.find(marker) {
        rest = &rest[start + marker.len()..];
        let Some(end) = rest.find('"') else {
            break;
        };
        names.insert(rest[..end].to_string());
        rest = &rest[end + 1..];
    }

    names
}

#[test]
fn test_verifier_diff_source_fixtures_cover_modeled_kfunc_signatures() {
    let signature_source = include_str!("../../instruction/kfunc_signature.rs");
    let verifier_diff = VERIFIER_DIFF_SOURCE_WITH_FIXTURES;

    let modeled = modeled_kfunc_signature_names(signature_source);
    let fixture_calls = verifier_diff_kfunc_call_names(verifier_diff);
    let missing = modeled
        .difference(&fixture_calls)
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "scripts/verifier_diff.nu source fixtures are missing modeled kfunc-call coverage for: {}",
        missing.join(", ")
    );
}

#[test]
fn test_verifier_diff_source_fixtures_cover_modeled_helper_names() {
    let instruction_source = include_str!("../../instruction.rs");
    let verifier_diff = VERIFIER_DIFF_SOURCE_WITH_FIXTURES;

    let modeled = modeled_helper_names(instruction_source);
    let fixture_calls = verifier_diff_helper_call_names(verifier_diff);
    let pending = BTreeSet::<String>::new();

    let missing = modeled
        .difference(&fixture_calls)
        .filter(|name| !pending.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let stale_pending = pending
        .difference(&modeled)
        .chain(pending.intersection(&fixture_calls))
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "scripts/verifier_diff.nu source fixtures are missing modeled helper-call coverage for: {}",
        missing.join(", ")
    );
    assert!(
        stale_pending.is_empty(),
        "verifier_diff helper-call pending coverage entries are stale or now covered: {}",
        stale_pending.join(", ")
    );
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
    let verifier_diff = VERIFIER_DIFF_SOURCE;
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

#[test]
fn test_verifier_diff_fixture_summary_reports_too_new_kfunc_window() {
    let script = r#"source scripts/verifier_diff.nu
let fixture = {
    name: "unit-kfunc-window"
    category: "kfunc"
    target: "struct_ops:sched_ext_ops"
    program: [
        "{"
        "    name: \"nu.demo_1\""
        "    cpu_release: {|ctx|"
        "        let ignored = (kfunc-call \"scx_bpf_reenqueue_local\")"
        "        0"
        "    }"
        "}"
    ]
    local: "accept"
    kernel: "skip"
}
let features = (fixture-kernel-features $fixture)
let derived = (fixture-derived-metadata $fixture $features)
let summary = (fixture-summary-from-derived $derived "6.23.0")
{
    effective_min_kernel: $summary.effective_min_kernel
    effective_max_kernel_exclusive: $summary.effective_max_kernel_exclusive
    effective_max_kernel_exclusive_sources: $summary.effective_max_kernel_exclusive_sources
    compatible_with_compat_kernel: $summary.compatible_with_compat_kernel
    compat_kernel_reason: $summary.compat_kernel_reason
    kernel_features: (kernel-feature-labels $summary.kernel_features)
} | to json"#;

    let Some(output) = run_nu_script(script, "compat-kernel max-exclusive kfunc summary") else {
        return;
    };
    assert!(
        output.status.success(),
        "verifier_diff.nu compat-kernel summary failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("verifier_diff.nu compat-kernel summary should emit JSON");
    assert_eq!(
        actual
            .get("effective_min_kernel")
            .and_then(serde_json::Value::as_str),
        Some("6.12")
    );
    assert_eq!(
        actual
            .get("effective_max_kernel_exclusive")
            .and_then(serde_json::Value::as_str),
        Some("6.23")
    );
    let max_sources = actual
        .get("effective_max_kernel_exclusive_sources")
        .and_then(serde_json::Value::as_array)
        .expect("summary should include effective max-kernel source list");
    assert!(max_sources.iter().any(|source| {
        source
            .as_str()
            .is_some_and(|source| source.contains("kernel/sched/ext.c"))
    }));
    assert_eq!(
        actual
            .get("compatible_with_compat_kernel")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        actual
            .get("compat_kernel_reason")
            .and_then(serde_json::Value::as_str),
        Some("kernel<6.23")
    );
    let feature_labels = actual
        .get("kernel_features")
        .and_then(serde_json::Value::as_array)
        .expect("summary should include kernel feature labels");
    assert!(feature_labels.iter().any(|label| {
        label
            .as_str()
            .is_some_and(|label| label.contains("kfunc:scx_bpf_reenqueue_local>=6.12,<6.23"))
    }));
}

#[test]
fn test_verifier_diff_matrix_counts_bounded_kernel_windows() {
    let script = r#"source scripts/verifier_diff.nu
let bounded = {
    name: "unit-bounded-kfunc-window"
    category: "kfunc"
    target: "struct_ops:sched_ext_ops"
    program: [
        "{"
        "    name: \"nu.demo_1\""
        "    cpu_release: {|ctx|"
        "        let ignored = (kfunc-call \"scx_bpf_reenqueue_local\")"
        "        0"
        "    }"
        "}"
    ]
    local: "accept"
    kernel: "accept"
}
let unbounded = {
    name: "unit-unbounded-kfunc"
    category: "kfunc"
    target: "kprobe:ksys_read"
    program: [
        "{|ctx|"
        "  let ignored = (kfunc-call \"bpf_get_task_exe_file\")"
        "  0"
        "}"
    ]
    local: "accept"
    kernel: "accept"
}
let derived = (
    [$bounded $unbounded]
    | each {|fixture|
        let features = (fixture-kernel-features $fixture)
        fixture-derived-metadata $fixture $features
    }
)
fixture-matrix-rows-from-derived $derived "6.23.0"
| where category == "kfunc"
| first
| to json"#;

    let Some(output) = run_nu_script(script, "compat-kernel bounded matrix counts") else {
        return;
    };
    assert!(
        output.status.success(),
        "verifier_diff.nu compat-kernel matrix failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("verifier_diff.nu compat-kernel matrix should emit JSON");
    let int_field = |field: &str| {
        actual
            .get(field)
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(|| panic!("matrix row should include integer field {field}"))
    };

    assert_eq!(int_field("kernel_accept"), 2);
    assert_eq!(int_field("kernel_accept_versioned"), 2);
    assert_eq!(int_field("kernel_accept_unversioned"), 0);
    assert_eq!(int_field("kernel_accept_bounded"), 1);
    assert_eq!(int_field("kernel_accept_unbounded"), 1);
    assert_eq!(int_field("kernel_accept_compatible"), 1);
    assert_eq!(int_field("kernel_accept_incompatible"), 1);
    assert_eq!(int_field("kernel_accept_requires_newer"), 0);
    assert_eq!(int_field("kernel_accept_requires_older"), 1);
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

#[test]
fn test_verifier_diff_context_field_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
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

    let checks = expected
        .iter()
        .map(|check| (check.target.clone(), check.field.clone()))
        .collect::<Vec<_>>();
    let Some(actual) =
        verifier_diff_nu_field_target_feature_records("context-field-kernel-feature", &checks)
    else {
        return;
    };

    let mut mismatches = Vec::new();
    for (check, record) in expected.iter().zip(actual.iter()) {
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
fn test_verifier_diff_nested_record_wrapper_read_scanner_preserves_metadata() {
    let target = "kprobe:ksys_read";
    let program = r#"{|ctx|
  def wrap [event] { { event: $event } }
  def outer [event] { wrap $event }
  let rec = (outer $ctx)
  $rec.event.pid | count
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected =
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Pid, &spec)
            .expect("ctx.pid should carry source-backed context metadata")
            .key();

    assert!(
        actual[0].contains(&expected),
        "nested user-function record wrappers should preserve read-side context metadata; expected {expected}, actual {:?}",
        actual[0]
    );
}

#[test]
fn test_verifier_diff_identity_wrapper_record_argument_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def id [value] { $value }
  def wrap [event] { { socket: $event } }
  let rec = (wrap (id ($ctx | get sk)))
  $rec.socket.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "transparent identity wrappers around record-wrapper arguments should preserve context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_user_function_read_scanner_preserves_metadata() {
    let target = "kprobe:ksys_read";
    let program = r#"{|ctx|
  def read_pid [ignored event] { $event.pid }
  read_pid 0 $ctx
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Pid, &spec)
            .expect("ctx.pid should carry source-backed context metadata")
            .key(),
        BpfHelper::GetCurrentPidTgid
            .compatibility_requirement()
            .expect("ctx.pid backing helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve read-side context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_user_function_get_read_scanner_preserves_metadata() {
    let target = "kprobe:ksys_read";
    let program = r#"{|ctx|
  def read_pid [ignored event] { $event | get pid }
  read_pid 0 $ctx
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Pid, &spec)
            .expect("ctx.pid should carry source-backed context metadata")
            .key(),
        BpfHelper::GetCurrentPidTgid
            .compatibility_requirement()
            .expect("ctx.pid backing helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve get-pipeline context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_user_function_root_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def get_sk [ignored event] { $event.sk }
  let sk = (get_sk 0 $ctx)
  $sk.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve returned context-root metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_user_function_get_root_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def get_sk [ignored event] { $event | get sk }
  let sk = (get_sk 0 $ctx)
  $sk.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve get-pipeline returned-root metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_alias_read_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def read_family [ignored event] {
    let sk = $event.sk
    $sk.family
  }
  read_family 0 $ctx
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve context-root alias read metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_get_alias_read_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def read_family [ignored event] {
    let sk = ($event | get sk)
    $sk.family
  }
  read_family 0 $ctx
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve get-derived context-root alias metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_get_argument_root_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def get_it [ignored event] { $event }
  let sk = (get_it 0 ($ctx | get sk))
  $sk.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve get-pipeline context argument metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_record_wrapper_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def wrap [ignored event] { { socket: $event.sk } }
  let rec = (wrap 0 $ctx)
  $rec.socket.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter record wrappers should preserve context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_get_argument_record_wrapper_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def wrap [ignored event] { { socket: $event } }
  let rec = (wrap 0 ($ctx | get sk))
  $rec.socket.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter record wrappers should preserve get-pipeline context argument metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_identity_wrapper_record_argument_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def id [value] { $value }
  def wrap [ignored event] { { socket: $event } }
  let rec = (wrap 0 (id ($ctx | get sk)))
  $rec.socket.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "transparent identity wrappers around multi-parameter record-wrapper arguments should preserve context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_identity_wrapper_record_field_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def id [value] { $value }
  def wrap [ignored event] { { socket: (id ($event | get sk)) } }
  let rec = (wrap 0 $ctx)
  $rec.socket.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "transparent identity wrappers around multi-parameter record-wrapper fields should preserve context metadata"
    );
}

#[test]
fn test_verifier_diff_program_surface_scanner_matches_rust_helper_keys() {
    struct SurfaceScannerCheck {
        target: &'static str,
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let sk_lookup_spec = ProgramSpec::parse("sk_lookup:/proc/self/ns/net")
        .unwrap_or_else(|err| panic!("sk_lookup spec should parse: {err}"));
    let sk_lookup_ctx_sk = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
        &CtxField::Socket,
        &sk_lookup_spec,
    )
    .expect("sk_lookup ctx.sk should carry compatibility metadata")
    .key();

    let mut checks = vec![
        SurfaceScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  tail-call progs 0
  random int
  read-str 0 8
  read-kernel-str 0 8
  emit events { pid: 1 }
  count counts 0
  histogram latency 1
  start-timer timers 0
  stop-timer timers 0
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::TailCall,
                BpfHelper::GetPrandomU32,
                BpfHelper::ProbeReadUserStr,
                BpfHelper::ProbeReadKernelStr,
                BpfHelper::RingbufOutput,
                BpfHelper::MapLookupElem,
                BpfHelper::MapUpdateElem,
                BpfHelper::GetCurrentPidTgid,
                BpfHelper::KtimeGetNs,
                BpfHelper::MapDeleteElem,
            ]),
        },
        SurfaceScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  map-get counts 0 --kind hash
  map-put counts 0 1 --kind hash
  map-delete counts 0 --kind hash
  map-push queue 1 --kind queue
  map-peek queue --kind queue
  map-pop queue --kind queue
  map-contains bloom 1 --kind bloom-filter
  redirect-map devmap 0
  adjust-packet --pull 0
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::MapLookupElem,
                BpfHelper::MapUpdateElem,
                BpfHelper::MapDeleteElem,
                BpfHelper::MapPushElem,
                BpfHelper::MapPeekElem,
                BpfHelper::MapPopElem,
                BpfHelper::RedirectMap,
                BpfHelper::SkbPullData,
            ]),
        },
        SurfaceScannerCheck {
            target: "sk_msg:/sys/fs/bpf/demo_sockmap",
            program: r#"{|ctx|
  adjust-message --apply 8
  adjust-message --cork 8
  adjust-message --pull 0 1
  adjust-message --push 0 1
  adjust-message --pop 0 1
  redirect-socket peers 0 --kind sockhash
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::MsgApplyBytes,
                BpfHelper::MsgCorkBytes,
                BpfHelper::MsgPullData,
                BpfHelper::MsgPushData,
                BpfHelper::MsgPopData,
                BpfHelper::MsgRedirectHash,
            ]),
        },
        SurfaceScannerCheck {
            target: "sk_msg:/sys/fs/bpf/demo_sockmap",
            program: r#"{|ctx|
  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" 0
  redirect-socket hash_peers "peer-b"
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::MsgRedirectHash]),
        },
        SurfaceScannerCheck {
            target: "sk_skb:/sys/fs/bpf/demo_sockmap",
            program: r#"{|ctx|
  redirect-socket peers 0 --kind sockmap
  redirect-socket hash_peers 0 --kind sockhash
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::SkRedirectMap,
                BpfHelper::SkRedirectHash,
            ]),
        },
        SurfaceScannerCheck {
            target: "sk_reuseport:migrate",
            program: r#"{|ctx|
  redirect-socket sockets 0 --kind reuseport-sockarray
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::SkSelectReuseport]),
        },
        SurfaceScannerCheck {
            target: "tc:lo:ingress",
            program: r#"{|ctx|
  map-contains tracked_cgroups 0 --kind cgroup-array
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::SkbUnderCgroup]),
        },
        SurfaceScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  map-contains tracked_cgroups 0 --kind cgroup-array
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::CurrentTaskUnderCgroup]),
        },
        SurfaceScannerCheck {
            target: "sk_lookup:/proc/self/ns/net",
            program: r#"{|ctx|
  assign-socket 0 --replace
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::SkAssign]),
        },
    ];
    checks
        .last_mut()
        .expect("expected assign-socket surface check")
        .expected_keys
        .insert(sk_lookup_ctx_sk);

    let nu_checks = checks
        .iter()
        .map(|check| (check.target.to_string(), check.program.to_string()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_surface_feature_keys(&nu_checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} {} expected {:?} actual {:?}",
                index, check.target, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-surface scanner drifted from Rust helper metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_program_helper_scanner_matches_rust_helper_keys() {
    struct HelperScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        HelperScannerCheck {
            program: r#"{|ctx|
  let text = "helper-call \"bpf_trace_printk\" \"ignored\" 7"
  # helper-call "bpf_map_lookup_elem" ignored key
  let ignored = 0 # | helper-call "bpf_ktime_get_ns"
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  let arg0 = "01234567"
  let retval = "01234567"
  (helper-call "bpf_get_func_arg" $ctx 0 $arg0) | count
  (helper-call "bpf_get_func_ret" $ctx $retval) | count
  (helper-call "bpf_get_func_arg_cnt" $ctx) | count
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::GetFuncArg,
                BpfHelper::GetFuncRet,
                BpfHelper::GetFuncArgCnt,
            ]),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  map-define nsdata --kind array --value-type bytes:8 --max-entries 1
  let ns = (0 | map-get nsdata)
  if $ns {
    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8
  }
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::GetNsCurrentPidTgid]),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  map-define fib_params --kind array --value-type bytes:64 --max-entries 1
  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1
  let params = (0 | map-get fib_params --kind array)
  let len = (0 | map-get mtu_len --kind array)
  helper-call "bpf_skb_cgroup_classid" $ctx
  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }
  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::SkbCgroupClassid,
                BpfHelper::FibLookup,
                BpfHelper::CheckMtu,
            ]),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  let key = "01234567"
  helper-call "bpf_map_lookup_percpu_elem" per_cpu_values $key 0 --kind per-cpu-array
  let tuple = "0123456789abcdef"
  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)
  if $sk {
    helper-call "bpf_sk_release" $sk
  }
  "pass"
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::MapLookupPercpuElem,
                BpfHelper::SkLookupTcp,
                BpfHelper::SkRelease,
            ]),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"
  let entry = (0 | map-get timers --kind array)
  if $entry {
    helper-call "bpf_timer_init" $entry.timer timers 0 --kind array
    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 0}
    helper-call "bpf_timer_start" $entry.timer 1000 0
    helper-call "bpf_timer_cancel" $entry.timer
  }
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::TimerInit,
                BpfHelper::TimerSetCallback,
                BpfHelper::TimerStart,
                BpfHelper::TimerCancel,
            ]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_helper_feature_keys(&programs) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} expected {:?} actual {:?}",
                index, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-helper scanner drifted from Rust helper metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_program_kfunc_scanner_matches_rust_kfunc_keys() {
    struct KfuncScannerCheck {
        target: &'static str,
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  let text = "kfunc-call \"bpf_task_from_pid\" 1"
  # kfunc-call "bpf_task_from_pid" 1
  let ignored = 0 # | kfunc-call "bpf_task_from_pid" 1
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  kfunc-call "bpf_rcu_read_lock"
  kfunc-call "bpf_rcu_read_unlock"
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "raw_tracepoint:sys_enter",
                ["bpf_rcu_read_lock", "bpf_rcu_read_unlock"],
            ),
        },
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  kfunc-call "bpf_preempt_disable"
  kfunc-call "bpf_preempt_enable"
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "raw_tracepoint:sys_enter",
                ["bpf_preempt_disable", "bpf_preempt_enable"],
            ),
        },
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  let flags = "00000000"
  kfunc-call "bpf_local_irq_save" $flags
  kfunc-call "bpf_local_irq_restore" $flags
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "raw_tracepoint:sys_enter",
                ["bpf_local_irq_save", "bpf_local_irq_restore"],
            ),
        },
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  let flags = "00000000"
  kfunc-call "bpf_res_spin_lock" $ctx.current_task
  kfunc-call "bpf_res_spin_unlock" $ctx.current_task
  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags
  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "raw_tracepoint:sys_enter",
                [
                    "bpf_res_spin_lock",
                    "bpf_res_spin_unlock",
                    "bpf_res_spin_lock_irqsave",
                    "bpf_res_spin_unlock_irqrestore",
                ],
            ),
        },
        KfuncScannerCheck {
            target: "tc:lo:ingress",
            program: r#"{|ctx|
  let d = "0123456789abcdef"
  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target("tc:lo:ingress", ["bpf_dynptr_from_skb"]),
        },
        KfuncScannerCheck {
            target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
            program: r#"{|ctx|
  $ctx.sun_path = "/tmp/nu-ebpf.sock"
  "allow"
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
                ["bpf_sock_addr_set_sun_path"],
            ),
        },
    ];

    let nu_checks = checks
        .iter()
        .map(|check| (check.target.to_string(), check.program.to_string()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_kfunc_feature_keys(&nu_checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} {} expected {:?} actual {:?}",
                index, check.target, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-kfunc scanner drifted from Rust kfunc metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_program_struct_ops_scanner_matches_rust_sleepable_keys() {
    struct StructOpsScannerCheck {
        target: &'static str,
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let sleepable_keys = program_feature_keys([ProgramCompatibilityRequirement::SleepableProgram]);
    let checks = [
        StructOpsScannerCheck {
            target: "struct_ops:sched_ext_ops.init",
            program: r#"{|ctx|
  0
}"#,
            expected_keys: sleepable_keys.clone(),
        },
        StructOpsScannerCheck {
            target: "struct_ops:sched_ext_ops.select_cpu",
            program: r#"{|ctx|
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        StructOpsScannerCheck {
            target: "struct_ops:sched_ext_ops",
            program: r#"{
  init: {|ctx| 0 }
  select_cpu: {|ctx| 0 }
}"#,
            expected_keys: sleepable_keys.clone(),
        },
        StructOpsScannerCheck {
            target: "struct_ops:sched_ext_ops",
            program: r#"{
  let text = "init: {|ctx| 0 }"
  # init: {|ctx| 0 }
  select_cpu: {|ctx| 0 }
}"#,
            expected_keys: BTreeSet::new(),
        },
        StructOpsScannerCheck {
            target: "struct_ops:tcp_congestion_ops",
            program: r#"{
  init: {|ctx| 0 }
}"#,
            expected_keys: BTreeSet::new(),
        },
    ];

    let nu_checks = checks
        .iter()
        .map(|check| (check.target.to_string(), check.program.to_string()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_struct_ops_feature_keys(&nu_checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} {} expected {:?} actual {:?}",
                index, check.target, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-struct-ops scanner drifted from Rust sleepable metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_program_language_scanner_matches_rust_compiled_feature_keys() {
    struct LanguageScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        LanguageScannerCheck {
            program: r#"{|ctx|
  # def ignored [] { for ignored in 0..1 { } }
  let text = "def not_a_function [] { for item in [] { } }"
  1
}"#,
            expected_keys: BTreeSet::new(),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  def make [] { 7 }
  make
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BpfSubprogramCalls,
            ]),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  helper-call "bpf_loop" 4 {|i cb| 0 } "ctx" 0
  0
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BpfSubprogramCalls,
            ]),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key| 0} 0 0
  0
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BpfSubprogramCalls,
            ]),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  mut sum = 0
  for i in 0..3 {
    $sum = ($sum + $i)
  }
  $sum
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BoundedLoops,
            ]),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  def make [] { mut sum = 0; for i in 0..3 { $sum = ($sum + $i) }; $sum }
  make
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BpfSubprogramCalls,
                CompiledFeatureCompatibilityRequirement::BoundedLoops,
            ]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_language_feature_keys(&programs) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} expected {:?} actual {:?}",
                index, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-language scanner drifted from Rust compiled-feature metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_program_map_scanner_matches_rust_map_kind_keys() {
    struct MapScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        MapScannerCheck {
            program: r#"{|ctx|
  let text = "helper-call \"bpf_ringbuf_query\" custom_ringbuf 0"
  # helper-call "bpf_redirect_map" redirects 0 0 --kind devmap-hash
  let docs = "redirect-map tx_ports 0 --kind devmap"
  let more_docs = "map-define xsks --kind xskmap"
  let ignored = 0 # | helper-call "bpf_map_lookup_percpu_elem" values key 0 --kind lru-per-cpu-hash
  let more_ignored = 0 # | map-get values --kind queue
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  let entry = ($ctx.pid | map-get default_counts)
  if $entry { 1 | map-put default_counts $ctx.pid }
  $ctx.pid | map-delete default_counts
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::Hash]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  map-define array_counts --kind array --key-type u32 --value-type u64
  let entry = ($ctx.pid | map-get array_counts)
  1 | map-put array_counts $ctx.pid
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::Array]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  let entry = ($ctx.pid | map-get lru_counts --kind lru-hash)
  if $entry { 1 | map-put lru_counts $ctx.pid }
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::LruHash]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  map-define pending --kind queue --value-type u64
  1 | map-push pending
  map-peek pending
  map-pop pending
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::Queue]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  redirect-map tx_ports 0 --kind devmap
  redirect-map tx_ports 1
  redirect-socket peers 0 --kind sockhash
  redirect-socket peers 1
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::DevMap, MapKind::SockHash]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  helper-call "bpf_ringbuf_query" custom_ringbuf 0
  helper-call "bpf_get_stackid" $ctx custom_stacks 0
  helper-call "bpf_sk_redirect_hash" $ctx socket_hash 0 0
  helper-call "bpf_sk_storage_get" socket_storage $ctx.sk 0 0
  helper-call "bpf_map_push_elem" queue_or_bloom 1 0 --kind bloom-filter
  0
}"#,
            expected_keys: map_kind_feature_keys([
                MapKind::RingBuf,
                MapKind::StackTrace,
                MapKind::SockHash,
                MapKind::SkStorage,
                MapKind::BloomFilter,
            ]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  tail-call progs 0
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::ProgArray]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_map_feature_keys(&programs) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} expected {:?} actual {:?}",
                index, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-map scanner drifted from Rust map metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_program_map_value_scanner_matches_rust_map_value_keys() {
    struct MapValueScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        MapValueScannerCheck {
            program: r#"{|ctx|
  let text = "map-define resources --kind hash --value-type record{lock:bpf_spin_lock}"
  # map-define resources --kind hash --value-type "record{timer:bpf_timer}"
  map-define docs --kind hash # --value-type "record{lock:bpf_spin_lock}"
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define resources --kind hash --value-type "record{lock:bpf_spin_lock,timer:bpf_timer,task:kptr:task_struct,work:bpf_wq,refs:bpf_refcount}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfSpinLock,
                MapValueCompatibilityRequirement::BpfTimer,
                MapValueCompatibilityRequirement::BpfKptr,
                MapValueCompatibilityRequirement::BpfWorkqueue,
                MapValueCompatibilityRequirement::BpfRefcount,
            ]),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define list_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfSpinLock,
                MapValueCompatibilityRequirement::BpfListHead,
                MapValueCompatibilityRequirement::BpfListNode,
            ]),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define list_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfListHead,
                MapValueCompatibilityRequirement::BpfListNode,
                MapValueCompatibilityRequirement::BpfRefcount,
            ]),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:node_data:node}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfSpinLock,
                MapValueCompatibilityRequirement::BpfRbRoot,
                MapValueCompatibilityRequirement::BpfRbNode,
            ]),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb:record{refs:bpf_refcount,cookie:u64}}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfRbRoot,
                MapValueCompatibilityRequirement::BpfRbNode,
                MapValueCompatibilityRequirement::BpfRefcount,
            ]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_map_value_feature_keys(&programs) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} expected {:?} actual {:?}",
                index, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-map-value scanner drifted from Rust map-value metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_reserved_map_scanner_matches_rust_map_kind_keys() {
    struct ReservedMapScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        ReservedMapScannerCheck {
            program: r#"{|ctx|
  let text = "helper-call \"bpf_user_ringbuf_drain\" user_events"
  # helper-call "bpf_perf_event_read" perf_events 0
  let docs = "1 | emit"
  let more_docs = "2 | count"
  let ignored = 0 # | helper-call "bpf_get_stackid" $ctx kstacks 0
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        ReservedMapScannerCheck {
            program: r#"{|ctx|
  1 | emit
  2 | count
  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 0
  helper-call "bpf_perf_event_read" perf_events 0
  helper-call "bpf_get_stackid" $ctx kstacks 0
  0
}"#,
            expected_keys: map_kind_feature_keys([
                MapKind::RingBuf,
                MapKind::Hash,
                MapKind::UserRingBuf,
                MapKind::PerfEventArray,
                MapKind::StackTrace,
            ]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_reserved_map_feature_keys(&programs) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} expected {:?} actual {:?}",
                index, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu reserved-map scanner drifted from Rust map metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_program_global_scanner_matches_rust_global_keys() {
    struct GlobalScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let global_data_sections =
        global_feature_keys([GlobalCompatibilityRequirement::BpfDataSections]);
    let checks = [
        GlobalScannerCheck {
            program: r#"{|ctx|
  let text = "global-get seen"
  # 7 | global-define --type i64 seen
  let samples = []
  let payload = 0x[]
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  let config = { pid: 7 samples: [11 22] }
  (($config.samples | get 1) + $config.pid) | count
  0
}"#,
            expected_keys: global_data_sections.clone(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  let payload = 0x[01 02]
  ($payload | get 0) | count
  0
}"#,
            expected_keys: global_data_sections.clone(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  let config = { pid: $ctx.pid samples: [11 22] }
  (($config.samples | get 1) + $config.pid) | count
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  let seed = 7
  let config = { pid: $seed samples: [11 22] }
  (($config.samples | get 1) + $config.pid) | count
}"#,
            expected_keys: global_data_sections.clone(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  7 | global-define --type i64 seen
  global-get seen
}"#,
            expected_keys: global_data_sections.clone(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  mut state: record<pid: int stats: record<hits: int ok: bool>> = {}
  ($state.pid + $state.stats.hits) | count
  0
}"#,
            expected_keys: global_data_sections,
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_global_feature_keys(&programs) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} expected {:?} actual {:?}",
                index, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-global scanner drifted from Rust global metadata: {}",
        mismatches.join(", ")
    );
}

#[derive(Clone, Copy)]
enum ContextWriteScannerForm {
    Direct,
    RecordAlias,
    ReturnedContextAlias,
    RecordWrapper,
    RecordSpread,
    UserFunctionRecordWrapper,
    NestedUserFunctionRecordWrapper,
    RecordInsert,
    RecordUpdate,
    RecordUpsert,
    RecordGetAlias,
    RecordPipelineGetAlias,
    UserFunctionRecordGetAlias,
    UserFunctionRecordPipelineGetAlias,
    RecordSelect,
    RecordReject,
    RecordRename,
    RecordMerge,
    RecordDefault,
}

impl ContextWriteScannerForm {
    const ALL: [Self; 19] = [
        Self::Direct,
        Self::RecordAlias,
        Self::ReturnedContextAlias,
        Self::RecordWrapper,
        Self::RecordSpread,
        Self::UserFunctionRecordWrapper,
        Self::NestedUserFunctionRecordWrapper,
        Self::RecordInsert,
        Self::RecordUpdate,
        Self::RecordUpsert,
        Self::RecordGetAlias,
        Self::RecordPipelineGetAlias,
        Self::UserFunctionRecordGetAlias,
        Self::UserFunctionRecordPipelineGetAlias,
        Self::RecordSelect,
        Self::RecordReject,
        Self::RecordRename,
        Self::RecordMerge,
        Self::RecordDefault,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::RecordAlias => "record-alias",
            Self::ReturnedContextAlias => "returned-context-alias",
            Self::RecordWrapper => "record-wrapper",
            Self::RecordSpread => "record-spread",
            Self::UserFunctionRecordWrapper => "user-function-record-wrapper",
            Self::NestedUserFunctionRecordWrapper => "nested-user-function-record-wrapper",
            Self::RecordInsert => "record-insert",
            Self::RecordUpdate => "record-update",
            Self::RecordUpsert => "record-upsert",
            Self::RecordGetAlias => "record-get-alias",
            Self::RecordPipelineGetAlias => "record-pipeline-get-alias",
            Self::UserFunctionRecordGetAlias => "user-function-record-get-alias",
            Self::UserFunctionRecordPipelineGetAlias => "user-function-record-pipeline-get-alias",
            Self::RecordSelect => "record-select",
            Self::RecordReject => "record-reject",
            Self::RecordRename => "record-rename",
            Self::RecordMerge => "record-merge",
            Self::RecordDefault => "record-default",
        }
    }

    fn root(self) -> &'static str {
        match self {
            Self::Direct => "$ctx",
            Self::RecordAlias | Self::ReturnedContextAlias => "$event",
            Self::RecordGetAlias
            | Self::RecordPipelineGetAlias
            | Self::UserFunctionRecordGetAlias
            | Self::UserFunctionRecordPipelineGetAlias => "$event",
            Self::RecordWrapper
            | Self::RecordSpread
            | Self::UserFunctionRecordWrapper
            | Self::NestedUserFunctionRecordWrapper
            | Self::RecordInsert
            | Self::RecordUpdate
            | Self::RecordUpsert
            | Self::RecordSelect
            | Self::RecordReject
            | Self::RecordMerge
            | Self::RecordDefault => "$rec.event",
            Self::RecordRename => "$rec.alias",
        }
    }
}

fn context_write_scanner_assignment(
    field_name: &str,
    indexed: bool,
    form: ContextWriteScannerForm,
) -> String {
    let root = form.root();
    let assignment = if field_name == "flow_keys" {
        format!("  {root}.{field_name}.ip_proto = 6")
    } else if indexed {
        format!("  {root}.{field_name}.0 = 42")
    } else if matches!(field_name, "new_value" | "sysctl_new_value" | "sun_path") {
        format!("  {root}.{field_name} = \"1\"")
    } else {
        format!("  {root}.{field_name} = 1")
    };

    assignment
}

fn context_write_scanner_source_from_assignments(
    assignments: &[String],
    form: ContextWriteScannerForm,
) -> String {
    let assignments = assignments.join("\n");
    match form {
        ContextWriteScannerForm::Direct => format!("{{|ctx|\n{assignments}\n  \"allow\"\n}}"),
        ContextWriteScannerForm::RecordAlias => {
            format!("{{|ctx|\n  mut event = $ctx\n{assignments}\n  \"allow\"\n}}")
        }
        ContextWriteScannerForm::ReturnedContextAlias => format!(
            "{{|ctx|\n  def id [event] {{ $event }}\n  mut event = (id $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordWrapper => {
            format!("{{|ctx|\n  mut rec = {{ event: $ctx }}\n{assignments}\n  \"allow\"\n}}")
        }
        ContextWriteScannerForm::RecordSpread => format!(
            "{{|ctx|\n  let base = {{ event: $ctx }}\n  mut rec = {{ ok: true, ...$base }}\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordWrapper => format!(
            "{{|ctx|\n  def wrap [event] {{ {{ event: $event }} }}\n  mut rec = (wrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::NestedUserFunctionRecordWrapper => format!(
            "{{|ctx|\n  def wrap [event] {{ {{ event: $event }} }}\n  def outer [event] {{ wrap $event }}\n  mut rec = (outer $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordInsert => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | insert event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordUpdate => format!(
            "{{|ctx|\n  mut rec = ({{ event: 0 }} | update event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordUpsert => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | upsert event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordGetAlias => format!(
            "{{|ctx|\n  let rec = {{ event: $ctx }}\n  mut event = ($rec | get event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordPipelineGetAlias => format!(
            "{{|ctx|\n  mut event = ({{ other: 1 }} | insert event $ctx | get event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordGetAlias => format!(
            "{{|ctx|\n  def unwrap [event] {{\n    let rec = {{ event: $event }}\n    $rec | get event\n  }}\n  mut event = (unwrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordPipelineGetAlias => format!(
            "{{|ctx|\n  def unwrap [event] {{\n    {{ other: 1 }} | insert event $event | get event\n  }}\n  mut event = (unwrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordSelect => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx, other: 1 }} | select event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordReject => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx, other: 1 }} | reject other)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordRename => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx }} | rename alias)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordMerge => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | merge {{ event: $ctx }})\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordDefault => format!(
            "{{|ctx|\n  mut rec = ({{ }} | default $ctx event)\n{assignments}\n  \"allow\"\n}}"
        ),
    }
}

fn context_write_scanner_source(
    field_name: &str,
    indexed: bool,
    form: ContextWriteScannerForm,
) -> String {
    context_write_scanner_source_from_assignments(
        &[context_write_scanner_assignment(field_name, indexed, form)],
        form,
    )
}

#[test]
fn test_verifier_diff_context_write_scanner_covers_rust_write_surfaces() {
    #[derive(Clone)]
    struct ExpectedWriteFeature {
        target: String,
        form: &'static str,
        field_names: Vec<&'static str>,
        program: String,
        expected_keys: BTreeSet<String>,
    }

    let mut expected = Vec::new();

    for spec_text in REPRESENTATIVE_CONTEXT_WRITE_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text).unwrap_or_else(|err| {
            panic!("representative context write target {spec_text} should parse: {err}")
        });
        let write_surfaces = spec.ctx_write_surfaces_for_spec();
        for form in ContextWriteScannerForm::ALL {
            let mut assignments = Vec::new();
            let mut field_names = Vec::new();
            let mut expected_keys = BTreeSet::new();

            for surface in &write_surfaces {
                let Some(requirement) = surface.context_field_requirement.as_ref() else {
                    continue;
                };
                assignments.push(context_write_scanner_assignment(
                    surface.field_name,
                    surface.indexed,
                    form,
                ));
                field_names.push(surface.field_name);
                expected_keys.insert(requirement.key());
            }

            if !expected_keys.is_empty() {
                expected.push(ExpectedWriteFeature {
                    target: (*spec_text).to_string(),
                    form: form.label(),
                    field_names,
                    program: context_write_scanner_source_from_assignments(&assignments, form),
                    expected_keys,
                });
            }
        }
    }

    let checks = expected
        .iter()
        .map(|check| (check.target.clone(), check.program.clone()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (check, actual_keys) in expected.iter().zip(actual.iter()) {
        if actual_keys != &check.expected_keys {
            mismatches.push(format!(
                "{} {} ctx.{:?} expected {:?} actual {:?}",
                check.target, check.form, check.field_names, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu context write scanner drifted from Rust write surfaces: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_context_helper_write_scanner_covers_rust_write_surfaces() {
    #[derive(Clone)]
    struct ExpectedHelperWriteFeature {
        target: String,
        field_name: &'static str,
        form: &'static str,
        helper_name: &'static str,
        program: String,
        expected_keys: BTreeSet<String>,
    }

    let mut expected = Vec::new();

    for spec_text in REPRESENTATIVE_CONTEXT_WRITE_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text).unwrap_or_else(|err| {
            panic!("representative context write target {spec_text} should parse: {err}")
        });
        for surface in spec.ctx_write_surfaces_for_spec() {
            let Some(helper) = surface.helper else {
                continue;
            };
            let requirement =
                HelperCompatibilityRequirement::for_helper(helper).unwrap_or_else(|| {
                    panic!(
                        "{spec_text} ctx.{} helper {} should expose Rust metadata",
                        surface.field_name,
                        helper.name()
                    )
                });
            for form in ContextWriteScannerForm::ALL {
                expected.push(ExpectedHelperWriteFeature {
                    target: (*spec_text).to_string(),
                    field_name: surface.field_name,
                    form: form.label(),
                    helper_name: helper.name(),
                    program: context_write_scanner_source(
                        surface.field_name,
                        surface.indexed,
                        form,
                    ),
                    expected_keys: BTreeSet::from([requirement.key()]),
                });
            }
        }
    }

    let checks = expected
        .iter()
        .map(|check| (check.target.clone(), check.program.clone()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_surface_feature_keys(&checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (check, actual_keys) in expected.iter().zip(actual.iter()) {
        if actual_keys != &check.expected_keys {
            mismatches.push(format!(
                "{} {} ctx.{} {} expected {:?} actual {:?}",
                check.target,
                check.form,
                check.field_name,
                check.helper_name,
                check.expected_keys,
                actual_keys
            ));
        }
    }

    assert!(
        !expected.is_empty(),
        "expected at least one helper-backed context write surface"
    );
    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu helper-backed context write scanner drifted from Rust write surfaces: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_context_kfunc_write_scanner_covers_rust_write_surfaces() {
    #[derive(Clone)]
    struct ExpectedKfuncWriteFeature {
        target: String,
        field_name: &'static str,
        form: &'static str,
        kfunc: &'static str,
        program: String,
        expected_keys: BTreeSet<String>,
    }

    let mut expected = Vec::new();

    for spec_text in REPRESENTATIVE_CONTEXT_WRITE_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text).unwrap_or_else(|err| {
            panic!("representative context write target {spec_text} should parse: {err}")
        });
        for surface in spec.ctx_write_surfaces_for_spec() {
            let Some(kfunc) = surface.kfunc else {
                continue;
            };
            let requirement = spec
                .kfunc_compatibility_requirement_for_name(kfunc)
                .unwrap_or_else(|| {
                    panic!(
                        "{spec_text} ctx.{} should expose Rust metadata for {kfunc}",
                        surface.field_name
                    )
                });
            for form in ContextWriteScannerForm::ALL {
                expected.push(ExpectedKfuncWriteFeature {
                    target: (*spec_text).to_string(),
                    field_name: surface.field_name,
                    form: form.label(),
                    kfunc,
                    program: context_write_scanner_source(
                        surface.field_name,
                        surface.indexed,
                        form,
                    ),
                    expected_keys: BTreeSet::from([requirement.key()]),
                });
            }
        }
    }

    let checks = expected
        .iter()
        .map(|check| (check.target.clone(), check.program.clone()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_kfunc_feature_keys(&checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (check, actual_keys) in expected.iter().zip(actual.iter()) {
        if actual_keys != &check.expected_keys {
            mismatches.push(format!(
                "{} {} ctx.{} {} expected {:?} actual {:?}",
                check.target,
                check.form,
                check.field_name,
                check.kfunc,
                check.expected_keys,
                actual_keys
            ));
        }
    }

    assert!(
        !expected.is_empty(),
        "expected at least one kfunc-backed context write surface"
    );
    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu kfunc-backed context write scanner drifted from Rust write surfaces: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_target_context_field_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
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
    let verifier_diff = VERIFIER_DIFF_SOURCE;
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
fn test_verifier_diff_kfunc_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let explicit_records =
        verifier_diff_feature_table_records(verifier_diff, "KFUNC_KERNEL_FEATURES", "name");
    let fallback_records = verifier_diff_kfunc_fallback_records(verifier_diff);

    for (name, record) in &explicit_records {
        let requirement = KfuncCompatibilityRequirement::for_name(name).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu KFUNC_KERNEL_FEATURES has unknown kfunc {name}")
        });
        assert_verifier_feature_record_matches_kfunc_requirement(name, requirement, record);

        if let Some(fallback_record) = fallback_records.get(name) {
            assert_eq!(
                record, fallback_record,
                "scripts/verifier_diff.nu explicit and fallback kfunc metadata drifted for {name}"
            );
        }
    }

    for (name, record) in &fallback_records {
        let requirement = KfuncCompatibilityRequirement::for_name(name).unwrap_or_else(|| {
            panic!(
                "scripts/verifier_diff.nu KFUNC_KERNEL_FEATURE_FALLBACKS has unknown kfunc {name}"
            )
        });
        assert_verifier_feature_record_matches_kfunc_requirement(name, requirement, record);
    }

    assert!(
        !explicit_records.is_empty() && !fallback_records.is_empty(),
        "expected verifier_diff.nu kfunc feature metadata"
    );
}

#[test]
fn test_verifier_diff_program_kfunc_scanner_matches_program_specific_rust_floors() {
    let checks = [
        ("socket_filter:udp4:127.0.0.1:31337", "bpf_dynptr_from_skb"),
        ("tc:lo:ingress", "bpf_dynptr_from_skb"),
        ("tcx:lo:ingress", "bpf_dynptr_from_skb"),
        ("netkit:lo:primary", "bpf_dynptr_from_skb"),
        ("netfilter:ipv4:pre_routing", "bpf_dynptr_from_skb"),
        ("fentry:tcp_v4_rcv", "bpf_dynptr_from_skb"),
        ("fentry.s:tcp_v4_rcv", "bpf_dynptr_from_skb"),
        ("fexit:tcp_v4_rcv", "bpf_dynptr_from_skb"),
        ("fexit.s:tcp_v4_rcv", "bpf_dynptr_from_skb"),
        ("fmod_ret:bpf_modify_return_test", "bpf_dynptr_from_skb"),
        ("fmod_ret.s:bpf_modify_return_test", "bpf_dynptr_from_skb"),
        ("tp_btf:sys_enter", "bpf_dynptr_from_skb"),
        ("sock_ops:/sys/fs/cgroup", "bpf_sock_ops_enable_tx_tstamp"),
        (
            "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
            "bpf_sock_addr_set_sun_path",
        ),
    ]
    .into_iter()
    .map(|(target, kfunc)| (target.to_string(), kfunc.to_string()))
    .collect::<Vec<_>>();

    let Some(records) = verifier_diff_nu_program_kfunc_feature_records(&checks) else {
        return;
    };

    for ((target, kfunc), record) in checks.iter().zip(records.iter()) {
        let spec = ProgramSpec::parse(target).unwrap_or_else(|err| {
            panic!("program-specific kfunc target {target} should parse: {err}")
        });
        let requirement = spec
            .kfunc_compatibility_requirement_for_name(kfunc)
            .unwrap_or_else(|| {
                panic!(
                    "program-specific kfunc target {target} should expose Rust metadata for {kfunc}"
                )
            });
        assert_verifier_feature_record_matches_kfunc_requirement(
            &format!("{target} {kfunc}"),
            requirement,
            record,
        );
    }
}

#[test]
fn test_verifier_diff_tracepoint_payload_scanner_covers_all_modeled_rust_fallback_fields() {
    let checks = all_modeled_tracepoint_payload_scanner_checks();
    assert!(
        checks.len() > 500,
        "expected broad tracepoint payload scanner coverage, got {} checks",
        checks.len()
    );

    let Some(records) = verifier_diff_nu_field_target_feature_records(
        "tracepoint-payload-field-kernel-feature",
        &checks,
    ) else {
        return;
    };

    let mut mismatches = Vec::new();
    for ((target, field), record) in checks.iter().zip(records.iter()) {
        let spec = ProgramSpec::parse(target)
            .unwrap_or_else(|err| panic!("tracepoint target {target} should parse: {err}"));
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
            &CtxField::TracepointField(field.clone()),
            &spec,
        )
        .unwrap_or_else(|| panic!("{target} ctx.{field} should have Rust fallback metadata"));

        if !verifier_feature_record_matches_context_requirement(&requirement, record) {
            mismatches.push(format!(
                "{target} ctx.{field} expected key={} min_kernel={} source={} actual key={} min_kernel={} source={}",
                requirement.key(),
                requirement.minimum_kernel(),
                requirement.minimum_kernel_source(),
                record.key,
                record.min_kernel,
                record.source
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu tracepoint payload scanner drifted from all modeled Rust fallback metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_target_kernel_features_cover_representative_rust_program_specs() {
    let mut checks = Vec::new();

    for program_type in EbpfProgramType::supported_program_types() {
        let target = ProgramSpec::representative_target_for_program_type(*program_type);
        let spec = ProgramSpec::from_program_type_target(*program_type, target)
            .unwrap_or_else(|err| panic!("{program_type:?} representative target failed: {err}"));
        let expected_keys = spec
            .compatibility_requirements()
            .iter()
            .filter_map(|requirement| program_compatibility_verifier_feature_key(*requirement))
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        checks.push((spec.to_string(), expected_keys));
    }

    let targets = checks
        .iter()
        .map(|(target, _)| target.clone())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_target_feature_keys(&targets) else {
        return;
    };

    for ((target, expected_keys), actual_keys) in checks.iter().zip(actual.iter()) {
        assert_eq!(
            actual_keys, expected_keys,
            "scripts/verifier_diff.nu target-kernel-features drifted from ProgramSpec for {target}"
        );
    }
}

#[test]
fn test_verifier_diff_program_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
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
    let verifier_diff = VERIFIER_DIFF_SOURCE;
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
