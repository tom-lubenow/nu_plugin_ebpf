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
