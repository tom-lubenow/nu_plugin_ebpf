# nu_plugin_ebpf

A [Nushell](https://nushell.sh/) plugin that compiles Nushell closures to eBPF bytecode for kernel-level tracing and profiling.

## Features

- **Compile Nushell to eBPF**: write tracing and packet logic in familiar Nushell syntax
- **Attach families**: kprobe/kretprobe/kprobe.multi/kretprobe.multi/ksyscall/kretsyscall/uprobe/uretprobe/uprobe.multi/uretprobe.multi, fentry/fexit/fmod_ret/tp_btf/raw_tracepoint/raw_tracepoint.w/tracepoint/lsm (including sleepable `.s` BTF and user-probe sections), perf_event, XDP/TC/TCX/socket_filter/cgroup and `sk_*` packet paths, compile-only `flow_dissector`, `netfilter`, `lwt_*`, `tc_action`, `netkit`, `sk_reuseport`, `lsm_cgroup`, cgroup socket-address UNIX, `freplace`/extension, and `syscall` sections, `lirc_mode2`, and `struct_ops`
- **Typed kernel-BTF contexts**: named `ctx.arg.<name>` aliases, typed field projection, typed map round-tripping, and typed `struct_ops` callbacks
- **Small-state and aggregation tools**: leading typed `mut` bindings, named globals, generic maps, counters, histograms, timers, stacks, and event streaming

## Safety

- Most tracing paths are observational, but `struct_ops` can change kernel behavior.
- Live `struct_ops:sched_ext_ops` loads require `--unsafe-struct-ops`.
- `raw_tracepoint.w`, `fmod_ret`, `flow_dissector`, `netfilter`, `lwt_*`, `tc_action`, `netkit`, `sk_reuseport`, `lsm_cgroup`, `cgroup_sock_addr:*_unix`, `freplace`, and `syscall` currently support compile/dry-run only; live attach intentionally returns an unsupported error until the loader has a safe attach implementation.
- Prefer `--dry-run` on the host and use an isolated VM or disposable environment for risky `struct_ops` families.

## Project Status

This is an internal alpha, not a polished external release. The compiler has broad unit coverage and useful live support for the core tracing, packet, socket, cgroup, and TCX surfaces, plus compile/dry-run coverage for many advanced eBPF section families. The main remaining risks are kernel-version compatibility, incomplete live attach paths for newer program families, and verifier-parity gaps around richer helper/kfunc state transitions.

## Requirements

- Linux kernel 4.18+ for the basic tracing paths
- Linux kernel 5.5+ with `/sys/kernel/btf/vmlinux` for the kernel-BTF-backed paths (`fentry`, `fexit`, `fmod_ret`, `tp_btf`, named BTF args, `lsm`, `lsm_cgroup`, and `struct_ops`)
- Rust 2024 edition
- Root access or CAP_BPF capability

The compiler also tracks feature-style compatibility requirements for parsed
program specs. `ebpf spec` reports each requirement with a category, a default
test lane (`host-safe`, `host-gated`, `dry-run`, or `vm-only`), and nullable
minimum-kernel fields. Source-verified feature requirements carry minimum
kernel versions; mixed requirements stay nullable until they are split precisely
enough to avoid misleading compatibility claims. The kernel verifier remains
the final authority for unmodeled or version-specific behavior.

## Installation

```bash
cargo install --path .
```

Then register the plugin in Nushell:

```nushell
plugin add ~/.cargo/bin/nu_plugin_ebpf
plugin use ebpf
```

## Capability Setup

To run without root, grant BPF capabilities:

```bash
# One-time setup (requires root)
sudo setcap cap_bpf,cap_perfmon=ep ~/.cargo/bin/nu_plugin_ebpf

# Or run the setup command (applies changes when run as root)
ebpf setup
```

Verify capabilities:

```nushell
ebpf setup --check
```

Inspect how a target string is modeled before compiling it:

```nushell
ebpf spec 'fentry.s:do_sys_openat2'
ebpf spec --list
```

`ebpf spec` reports the parsed program type, context family, concrete context
argument and return-value surfaces when knowable, argument/return access mode,
packet context kind, direct packet-write support, modeled context fields with
type labels, pointer verifier facts, and any load guards, tracepoint payload
fields, nested context projections, writable context surfaces, return aliases,
target, aliases, parsed attach shape, section construction,
sleepable/BTF-callable metadata, kernel-target validation, capability labels,
supported first-class intrinsic commands, live-attach/default safety, and
compatibility requirement labels before you attempt to compile or attach a
closure.
The `context_projections` table lists projections that are valid for that
specific parsed target; attach-sensitive projections that would be rejected by
the compiler are omitted rather than advertised as unusable rows.

Structured `attach_shape` records are emitted for attach families where the
parsed target or attach resource changes compiler, loader, or verifier policy:
XDP mode/frags, perf-event source/sampling, socket-filter transport/family,
netns-scoped sk_lookup/flow_dissector, socket-map sk_msg/sk_skb hooks,
TC/TCX direction, TC action metadata, Netkit endpoint, sk_reuseport mode,
LWT hook, netfilter hook metadata, cgroup device/sysctl/sock_ops plus
socket/SKB/sockopt/socket-address variants, lirc devices, syscall/iterator
programs, and struct_ops roots/callbacks. Probe-like targets stay `generic`
when the target string already carries all currently modeled policy.

## Quick Start

### Count syscalls by process

```nushell
let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.comm | count }

sleep 5sec
ebpf counters $id | sort-by count --reverse
```

### Stream a named BTF field

```nushell
ebpf attach -s 'fentry:security_file_open' {|ctx|
    $ctx.arg.file.f_flags | emit
} | first 5
```

### Measure function latency

```nushell
let entry = ebpf attach --pin timing 'kprobe:vfs_read' {|| start-timer }
let exit = ebpf attach --pin timing 'kretprobe:vfs_read' {|| stop-timer | histogram }

sleep 5sec
ebpf histogram $exit
```

### Dry-run a struct_ops object

```nushell
ebpf attach --dry-run 'struct_ops:sched_ext_ops' {
    name: 'nu_demo'
}
```

## Recommended Patterns

- Prefer leading typed `mut` bindings for small private per-program state.
- Prefer ordinary Nushell expressions inside those bindings and typed `global-define --type` initializers. Arithmetic, cell-path projection, record/list construction, and string concatenation are intended surface forms when they stay compile-time constant and preserve an honest fixed layout.
- Use ordinary `random int` or `$ctx.random` when you need BPF pseudo-randomness; the zero-argument form, compile-time bounded ranges, and context field lower to `bpf_get_prandom_u32` without spelling a raw helper call.
- For scalar or scalar-record layouts whose size is fixed by the annotation alone, `mut state: ... = null` now zero-initializes that global without dropping to `global-define`.
- Typed record `mut` initializers may omit scalar or nested scalar-record fields that should start zeroed, as long as the annotation alone still fixes their honest layout. Typed list `mut` initializers may also seed fixed arrays from homogeneous scalar/binary/record constants when the initializer provides the concrete length, including when that list is nested inside a typed record global.
- Fixed-layout source records, including `record{...}` specs, typed `record<...>` mutable globals, and metadata-built record constants, use natural field alignment and an aligned array stride. Padding bytes are zero-filled by typed initializers and omitted from emitted BTF members.
- Use `global-define`, `global-get`, and `global-set` when you need an explicit shared name or a source-order-independent declaration.
  `global-define --type ...` now also accepts a compile-time constant initializer, typed record initializers may omit fields that should start zeroed, and a first `global-set` can now infer record layout and field semantics from metadata-built record values, including nested record builders, when their fields already have honest fixed layouts.
- Use `map-define --key-type/--value-type` when a named map key or value needs an explicit fixed layout before ordinary map operations can infer it. This is the source-level path for aggregate keys and verifier-managed map fields such as `bpf_timer` and `bpf_spin_lock`, for example `map-define timers --kind array --key-type u32 --value-type 'record{timer:bpf_timer,cookie:u64}' --max-entries 1024`. `--max-entries` sets positive map capacity for value-carrying map families that expose `max_entries`. Pinned peers attached with the same `--pin` group reuse those key/value schemas and capacity declarations when there is no conflict.
- Prefer the first-class packet/socket/message/map surface (`adjust-packet`, `adjust-message`, `redirect`, `redirect-map`, `redirect-socket`, `tail-call`, `map-contains`, socket-map `map-put`, and local-storage `map-get` / `map-contains` / `map-delete`) over raw `helper-call` forms when the operation matches; `redirect-socket` also covers `sk_reuseport` reuseport-sockarray selection.
- Treat `helper-call` and `kfunc-call` as escape hatches. Prefer typed context fields, ordinary Nushell control flow, and the smaller first-class command surface when it covers the operation.
- Use `--pin` when multiple probes need to share maps or timers.
- Use `--dry-run` first when exploring new kernels or high-risk attach families.

### Surface Policy

- The long-term first-class command surface is intentionally small: `emit`, `count`, `histogram`, `start-timer`, `stop-timer`, `read-str`, `read-kernel-str`, `adjust-packet`, `adjust-message`, `redirect`, `redirect-map`, `redirect-socket`, `tail-call`, and `map-contains`, plus the resource-oriented `map-*` / `global-*` surfaces.
- Ordinary Nushell primitives should stay ordinary when possible. For example, `random int` is supported directly rather than through a bespoke helper wrapper.
- `map-*` and `global-*` are convenience surfaces around real eBPF resources, not a second parallel language. Prefer ordinary Nushell variables and expressions until you truly need an explicit shared map/global resource.
- `helper-call` and `kfunc-call` are ABI escape hatches. They remain available, but the preferred direction is to keep lifting common operations into typed context projection and smaller first-class commands. `kfunc-call` can compile on broad helper-capable surfaces, while exact unmodeled kfunc allowlists remain kernel-verifier enforced.

## Documentation

- [Example Gallery](docs/examples.md): attach-family examples and common recipes
- [Language and Context Reference](docs/reference.md): context fields, program-family notes, language-surface policy, commands, helpers, tracepoint discovery, and limits
- [Development Guide](docs/development.md): manual integration harness and contributor-facing notes

## License

MIT
