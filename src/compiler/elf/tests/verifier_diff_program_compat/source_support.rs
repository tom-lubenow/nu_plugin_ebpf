use std::fs;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NU_SCRIPT_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) fn verifier_diff_source() -> String {
    crate::compiler::verifier_diff_test_support::verifier_diff_source()
}

pub(super) fn verifier_diff_source_with_fixtures() -> String {
    crate::compiler::verifier_diff_test_support::verifier_diff_source_with_fixture_chunks()
}

pub(super) const REPRESENTATIVE_CONTEXT_WRITE_SPEC_SOURCES: &[&str] = &[
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

pub(super) fn run_nu_script(script: &str, label: &str) -> Option<Output> {
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
