# nu_plugin_ebpf

A [Nushell](https://nushell.sh/) plugin that compiles Nushell closures to eBPF bytecode for kernel-level tracing and profiling.

## Features

- **Compile Nushell to eBPF**: write tracing and packet logic in familiar Nushell syntax
- **Attach families**: kprobe/kretprobe/uprobe/uretprobe, fentry/fexit/tp_btf/raw_tracepoint/tracepoint/lsm, perf_event, XDP/TC/socket_filter/cgroup and `sk_*` packet paths, `lirc_mode2`, and `struct_ops`
- **Typed kernel-BTF contexts**: named `ctx.arg.<name>` aliases, typed field projection, typed map round-tripping, and typed `struct_ops` callbacks
- **Small-state and aggregation tools**: leading typed `mut` bindings, named globals, generic maps, counters, histograms, timers, stacks, and event streaming

## Safety

- Most tracing paths are observational, but `struct_ops` can change kernel behavior.
- Live `struct_ops:sched_ext_ops` loads require `--unsafe-struct-ops`.
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
- Use `global-define`, `global-get`, and `global-set` when you need an explicit shared name or a source-order-independent declaration.
- Prefer the first-class redirect surface (`redirect`, `redirect-map`, and `redirect-socket`) over raw `helper-call` redirect helpers when the operation matches.
- Treat `helper-call` and `kfunc-call` as escape hatches. Prefer typed context fields, ordinary Nushell control flow, and the smaller first-class command surface when it covers the operation.
- Use `--pin` when multiple probes need to share maps or timers.
- Use `--dry-run` first when exploring new kernels or high-risk attach families.

## Documentation

- [Example Gallery](docs/examples.md): attach-family examples and common recipes
- [Language and Context Reference](docs/reference.md): context fields, program-family notes, language-surface policy, commands, helpers, tracepoint discovery, and limits
- [Development Guide](docs/development.md): manual integration harness and contributor-facing notes

## License

MIT
