# External Alpha Guide

This project is still an internal alpha. The safest external-consumption
posture is to inspect the target, dry-run first, then live-load only targets
whose status and prerequisites you understand.

## Status Labels

`ebpf spec TARGET` and `ebpf spec --list` expose `external_alpha_status`.
Treat that field as the source of truth for whether a modeled target is ready
for live experimentation.

| Status | Meaning |
|--------|---------|
| `live-supported` | Live attach is implemented and suitable for default host-safe alpha use, subject to normal kernel verifier checks. |
| `host-gated` | Live attach is implemented, but the target needs host resources, privileges, pinned maps, cgroups, interfaces, devices, BTF, tracefs, or bpffs setup. |
| `dry-run-only` | The compiler models the section and can usually emit/check an object, but this loader intentionally rejects live attach. |
| `vm-only` | The target can affect host behavior enough that alpha testing should happen in an isolated VM or disposable environment. |
| `unsafe-opt-in` | Live attach exists but requires an explicit unsafe flag, currently `--unsafe-struct-ops`, because the program can change host kernel behavior. |

## Suggested Workflow

1. Inspect the target before writing the program:

   ```nushell
   ebpf spec 'kprobe:sys_read' | select program_type external_alpha_status live_attach_status live_attach_default_test_lane compatibility_minimum_kernel
   ```

2. Dry-run the closure before live attach:

   ```nushell
   ebpf attach --dry-run 'kprobe:sys_read' {|ctx| $ctx.pid | count }
   ```

3. Live-load only after the dry-run object compiles and the target status is
   acceptable for the machine:

   ```nushell
   ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.pid | emit } | first 5
   ```

4. For `host-gated` targets, verify the required interface, cgroup, pinned
   map, device, tracefs/bpffs mount, BTF file, privileges, and kernel version
   yourself. The compiler can reject many known incompatibilities before load,
   but the kernel verifier and attach path remain authoritative.

5. For `dry-run-only`, `vm-only`, or `unsafe-opt-in` targets, keep host testing
   to `--dry-run` unless you are intentionally using an isolated environment.

## Packaging And Compatibility

External alpha users should build and register the plugin from the checked-out
repository:

```bash
cargo install --path .
```

The plugin currently tracks Nushell `0.110` crates. Use the same Nushell minor
version for `plugin add` / `plugin use`; after upgrading Nushell, rebuild the
plugin and re-register it if Nushell reports a protocol or signature mismatch.
There is not yet a binary distribution, package manager formula, or stable
plugin ABI promise.

The installed binary is usually `~/.cargo/bin/nu_plugin_ebpf`. Live attach
requires either root or Linux BPF capabilities on that exact binary:

```bash
sudo setcap cap_bpf,cap_perfmon=ep ~/.cargo/bin/nu_plugin_ebpf
```

Use `ebpf setup --check` to inspect the current capability state. Re-run
`setcap` after reinstalling because `cargo install` replaces the binary and can
drop capabilities. Some live targets still need additional host resources such
as tracefs, bpffs, BTF, cgroup v2, pinned maps, network interfaces, or device
nodes even when the binary has capabilities.

Kernel feature detection is best effort. The compiler checks source-backed
minimum and maximum-exclusive kernel windows that it knows about, but distro
backports, kernel config, disabled helpers/kfuncs, and attach-resource state
remain kernel-authoritative. Treat `--dry-run` as a compiler/object check, not
as a proof that live attach will succeed on every host.

## Status-Driven Examples

| Goal | Status to prefer | Example |
|------|------------------|---------|
| First live tracing test | `live-supported` | `kprobe:sys_read` |
| Tracepoint payload work | `live-supported` or `host-gated` | `tracepoint:syscalls/sys_enter_openat` |
| Packet or cgroup experiments | `host-gated` | `xdp:lo`, `tcx:lo:ingress`, `cgroup_skb:/sys/fs/cgroup:egress` |
| Advanced modeled sections | `dry-run-only` | `netfilter:ipv4:pre_routing:priority=-100:defrag` |
| Behavior-changing kernel hooks | `vm-only` or `unsafe-opt-in` | `struct_ops:sched_ext_ops` |

For a status-driven inventory, run:

```nushell
ebpf spec --list | select canonical_prefix external_alpha_status live_attach_default_test_lane live_attach_status
```

Use the result to choose a target before writing a larger program. If a target
is `dry-run-only`, keep the example as an object-generation or compiler
coverage test. If a target is `vm-only` or `unsafe-opt-in`, do not use it on a
production host.

## Safe Starting Points

Good first live examples are observational and bounded:

```nushell
ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.pid | emit } | first 5
ebpf attach -s 'tracepoint:syscalls/sys_enter_openat' {|ctx| $ctx.pid | emit } | first 5
ebpf attach -s 'perf_event:software:cpu-clock:period=100000' {|ctx| $ctx.cpu | emit } | first 5
```

Good first dry-run examples for richer surfaces:

```nushell
ebpf attach --dry-run 'fentry:security_file_open' {|ctx| $ctx.arg.file.f_flags | count }
ebpf attach --dry-run 'xdp:lo' {|ctx| $ctx.packet_len | count; 'pass' }
ebpf attach --dry-run 'netfilter:ipv4:pre_routing:priority=-100:defrag' {|ctx| $ctx.hook | count; 'accept' }
```

## Current Risk Shape

The core tracing paths are the best-supported live surface. Packet, socket,
cgroup, TC/TCX, and XDP targets are useful but commonly `host-gated` because
they need real host resources. Kernel-BTF-backed targets are useful when
`/sys/kernel/btf/vmlinux` is present and the target function/hook exists on
the running kernel.

Several advanced program families are intentionally compile/dry-run only until
the loader has a safe attach path: writable raw tracepoints, `fmod_ret`,
XDP devmap/cpumap secondary programs, `flow_dissector`, `netfilter`, `lwt_*`,
`tc_action`, `netkit`, `sk_reuseport`, `lsm_cgroup`, cgroup UNIX socket-address
hooks, `freplace`/extension, `syscall`, iterators that require a seq-file link,
and direct `struct_ops:<value_type>.<callback>` callback targets.

`struct_ops` object registration is behavior-changing. Unclassified
`struct_ops` families and high-risk families such as `sched_ext_ops`,
`hid_bpf_ops`, and `Qdisc_ops` require `--unsafe-struct-ops` for live attach
and should be tested in a VM or disposable environment first.

## Compatibility Limits

Compatibility metadata is source-backed when the project has a primary kernel
source for the claim. Local preflight compares the running kernel release
against known minimum and maximum-exclusive feature windows preserved in the
compiled object and includes the source URL for the effective minimum-kernel
floor when a too-old local kernel is rejected, or the maximum-window source
when a too-new kernel is rejected for a transitional kfunc. It does not prove
distro backports, kernel config, disabled helpers/kfuncs, tracefs/bpffs state,
cgroup/map/socket prerequisites, BTF availability, or every verifier rule.

When in doubt, use:

```nushell
ebpf spec TARGET
ebpf attach --dry-run TARGET { ... }
```

Then only live-load on a host where the failure mode is acceptable.

## Troubleshooting

If Nushell cannot load the plugin, confirm that the binary path passed to
`plugin add` exists, that the plugin was built against the same Nushell minor
version, and that `plugin use ebpf` has been run in the current session or
configuration.

If live attach fails before kernel load, inspect `ebpf spec TARGET` for
`external_alpha_status`, `live_attach_status`, `live_attach_unsupported_reason`,
`live_attach_opt_in_reason`, `capabilities`, and compatibility floors. Prefer
fixing the target, host prerequisites, or explicit opt-in flags before assuming
the kernel verifier is involved.

If live attach reaches the kernel and fails, keep the dry-run object as a
compiler artifact but treat the verifier/attach error as authoritative. Check
kernel version, BTF, tracefs/bpffs mounts, cgroup paths, pinned map paths,
network interface names, capabilities, and attach-family-specific resources.
