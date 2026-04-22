# nu_plugin_ebpf

A [Nushell](https://nushell.sh/) plugin that compiles Nushell closures to eBPF bytecode for kernel-level tracing and profiling.

## Features

- **Compile Nushell to eBPF**: write tracing and packet logic in familiar Nushell syntax
- **Attach families**: kprobe/kretprobe/uprobe/uretprobe, fentry/fexit/tp_btf/raw_tracepoint/raw_tracepoint.w/tracepoint/lsm (including sleepable `.s` BTF sections), perf_event, XDP/TC/socket_filter/cgroup and `sk_*` packet paths, compile-only `flow_dissector`, `netfilter`, `lwt_*`, `tc_action`, and `sk_reuseport`, `lirc_mode2`, and `struct_ops`
- **Typed kernel-BTF contexts**: named `ctx.arg.<name>` aliases, typed field projection, typed map round-tripping, and typed `struct_ops` callbacks
- **Small-state and aggregation tools**: leading typed `mut` bindings, named globals, generic maps, counters, histograms, timers, stacks, and event streaming

## Safety

- Most tracing paths are observational, but `struct_ops` can change kernel behavior.
- Live `struct_ops:sched_ext_ops` loads require `--unsafe-struct-ops`.
- `raw_tracepoint.w`, `flow_dissector`, `netfilter`, `lwt_*`, `tc_action`, and `sk_reuseport` currently support compile/dry-run only; live attach intentionally returns an unsupported error until the loader has a safe attach implementation.
- Prefer `--dry-run` on the host and use an isolated VM or disposable environment for risky `struct_ops` families.

## Requirements

- Linux kernel 4.18+ for the basic tracing paths
- Linux kernel 5.5+ with `/sys/kernel/btf/vmlinux` for the kernel-BTF-backed paths (`fentry`, `fexit`, `tp_btf`, named BTF args, `lsm`, and `struct_ops`)
- Rust 2024 edition
- Root access or CAP_BPF capability

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
- Use ordinary `random int` when you need BPF pseudo-randomness; the zero-argument form and compile-time bounded ranges lower to `bpf_get_prandom_u32` without spelling a raw helper call.
- For scalar or scalar-record layouts whose size is fixed by the annotation alone, `mut state: ... = null` now zero-initializes that global without dropping to `global-define`.
- Typed record `mut` initializers may omit scalar or nested scalar-record fields that should start zeroed, as long as the annotation alone still fixes their honest layout. Typed list `mut` initializers may also seed fixed arrays from homogeneous scalar/binary/record constants when the initializer provides the concrete length, including when that list is nested inside a typed record global.
- Use `global-define`, `global-get`, and `global-set` when you need an explicit shared name or a source-order-independent declaration.
  `global-define --type ...` now also accepts a compile-time constant initializer, typed record initializers may omit fields that should start zeroed, and a first `global-set` can now infer record layout and field semantics from metadata-built record values, including nested record builders, when their fields already have honest fixed layouts.
- Prefer the first-class packet/socket/message/map surface (`adjust-packet`, `adjust-message`, `redirect`, `redirect-map`, `redirect-socket`, `tail-call`, `map-contains`, socket-map `map-put`, and local-storage `map-get` / `map-contains` / `map-delete`) over raw `helper-call` forms when the operation matches.
- Treat `helper-call` and `kfunc-call` as escape hatches. Prefer typed context fields, ordinary Nushell control flow, and the smaller first-class command surface when it covers the operation.
- Use `--pin` when multiple probes need to share maps or timers.
- Use `--dry-run` first when exploring new kernels or high-risk attach families.

### Surface Policy

- The long-term first-class command surface is intentionally small: `emit`, `count`, `histogram`, `start-timer`, `stop-timer`, `read-str`, `read-kernel-str`, `adjust-packet`, `adjust-message`, `redirect`, `redirect-map`, `redirect-socket`, `tail-call`, and `map-contains`, plus the resource-oriented `map-*` / `global-*` surfaces.
- Ordinary Nushell primitives should stay ordinary when possible. For example, `random int` is supported directly rather than through a bespoke helper wrapper.
- `map-*` and `global-*` are convenience surfaces around real eBPF resources, not a second parallel language. Prefer ordinary Nushell variables and expressions until you truly need an explicit shared map/global resource.
- `helper-call` and `kfunc-call` are ABI escape hatches. They remain available, but the preferred direction is to keep lifting common operations into typed context projection and smaller first-class commands.

## Documentation

- [Example Gallery](docs/examples.md): attach-family examples and common recipes
- [Language and Context Reference](docs/reference.md): context fields, program-family notes, language-surface policy, commands, helpers, tracepoint discovery, and limits
- [Development Guide](docs/development.md): manual integration harness and contributor-facing notes

## License

MIT
