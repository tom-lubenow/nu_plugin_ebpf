# nu_plugin_ebpf

A [Nushell](https://nushell.sh/) plugin that compiles Nushell closures to eBPF bytecode for kernel-level tracing and profiling.

## Features

- **Compile Nushell to eBPF**: Write tracing logic in familiar Nushell syntax
- **Multiple attach types**: kprobe, kretprobe, fentry, fexit, tracepoint, uprobe, uretprobe
- **Aggregations**: Count by key, histograms, timing measurements
- **Event streaming**: Real-time event output via ring buffers
- **Map sharing**: Share data between probes with `--pin`

## Requirements

- Linux kernel 4.18+ for the basic tracing paths
- Linux kernel 5.5+ with `/sys/kernel/btf/vmlinux` for `fentry` and `fexit`
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

### Stream events from a kernel function

```nushell
# Stream PIDs calling sys_clone (Ctrl-C to stop)
ebpf attach --stream 'kprobe:sys_clone' {|ctx| $ctx.pid | emit }

# Capture first 10 sys_read calls
ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.tgid | emit } | first 10

# Capture first 10 fentry hits on ksys_read
ebpf attach -s 'fentry:ksys_read' {|ctx| $ctx.pid | emit } | first 10

# Capture the first filename seen by do_sys_openat2
ebpf attach -s 'fentry:do_sys_openat2' {|ctx|
    if $ctx.arg1 != 0 { $ctx.arg1 | read-str --max-len 64 | emit }
} | first 1

# Capture openat2 flags from a pointer-backed trampoline arg
ebpf attach -s 'fentry:do_sys_openat2' {|ctx| $ctx.arg2.flags | emit } | first 1

# Capture the first ksys_read return value
ebpf attach -s 'fexit:ksys_read' {|ctx| $ctx.retval | emit } | first 1
```

### Count syscalls by process

```nushell
# Attach probe (returns probe ID)
let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.comm | count }

# Let it run, then read counters
sleep 5sec
ebpf counters $id | sort-by count --reverse
```

### Measure function latency

```nushell
# Start timer on entry
let entry = ebpf attach --pin timing 'kprobe:vfs_read' {|ctx|
    start-timer
}

# Stop timer and emit latency on return
let exit = ebpf attach --pin timing 'kretprobe:vfs_read' {|ctx|
    stop-timer | histogram
}

# View latency distribution
sleep 5sec
ebpf histogram $exit
```

### Trace file opens with filenames

```nushell
ebpf attach -s 'tracepoint:syscalls/sys_enter_openat' {|ctx|
    { pid: $ctx.pid, file: ($ctx.filename | read-str) } | emit
}
```

## Manual Integration Suite

Run the repeatable manual integration checks (requires `sudo` and a built release plugin):

```bash
cargo build --release
./scripts/manual_integration.sh
```

Override tool paths if needed:

```bash
NU_BIN=/path/to/nu PLUGIN_BIN=/path/to/nu_plugin_ebpf ./scripts/manual_integration.sh
```

## Context Fields

The closure receives a context parameter with these fields:

| Field | Description | Probe Types |
|-------|-------------|-------------|
| `pid` | Thread ID | All |
| `tgid` | Process ID (thread group) | All |
| `uid` | User ID | All |
| `gid` | Group ID | All |
| `comm` | Process name (16 bytes) | All |
| `ktime` | Kernel timestamp (ns) | All |
| `arg0`-`argN` | Function arguments | kprobe, uprobe, fentry, fexit |
| `retval` | Return value | kretprobe, uretprobe, fexit |

Tracepoint fields are read from `/sys/kernel/tracing/events/<category>/<name>/format`.

`kprobe` and `uprobe` expose `ctx.arg0`-`ctx.arg5` through `pt_regs`. `fentry` and
`fexit` resolve `ctx.argN` and `ctx.retval` through kernel BTF. Scalar and pointer
trampoline values work directly. By-value trampoline args and pointer-backed
trampoline args/returns can project scalar/pointer fields such as
`ctx.arg0.some_field`; pointer-backed projections are lowered through
null-guarded `bpf_probe_read_{kernel,user}` and can cross intermediate and
repeated pointer hops such as `ctx.arg0.foo.bar` or
`ctx.arg0.fdt.fd.f_inode.i_ino`. Fixed-size arrays can also be indexed with
numeric path segments like `ctx.arg0.comm.0`, and pointer-backed sequences
can now also be indexed with constant numeric segments such as
`ctx.arg0.fdt.fd.0.f_inode.i_ino` or `let fd = $ctx.arg0.fdt.fd;
$fd.0.f_inode.i_ino`. The same typed pointer traversal also works through
numeric `get`, for example `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get
$idx); $fd.f_inode.i_ino`. Stack-backed fixed arrays support the same runtime
indexing, for example `let idx = ($ctx.pid mod 2); ($ctx.arg0.comm | get
$idx)`. Bounded ascending `for` loops over static integer
ranges also lower to verifier-safe loops, so `for i in 0..0 { ... get $i ...
}` now works, and bounded arithmetic on those indices such as
`let j = (($i + 1) mod 2)` is preserved too. The same range tracking now
works for typed unsigned runtime fields such as
`let idx = ($ctx.arg0.fdt.max_fds mod 2)`; descending ranges are still
rejected. Branch-sensitive narrowing also works for both bound and repeated
direct paths, for example `let max = $ctx.arg0.fdt.max_fds; if $max > 0 {
let idx = ($max - 1); ... }` or `if $ctx.arg0.fdt.max_fds > 0 { let idx =
($ctx.arg0.fdt.max_fds - 1); ... }`. Terminal array leaves and unsupported aggregate
leaves are exposed as stack-backed byte buffers, while representable terminal struct
leaves keep their field layouts for `count`/`ebpf counters`, and single-value
`emit` can stream those struct leaves as records. Nested array/record fields
inside emitted values also decode recursively when the compiler can preserve
their layouts. `emit` still preserves unsupported aggregate layouts as binary
payloads, and `count` supports them as byte-buffer keys. `ebpf counters`
decodes those keys using any schema the compiler still has: arrays and typed
structs can surface as strings, lists, or records, while opaque aggregate
layouts still display as `binary`. Plain trampoline `ctx.argN`/`ctx.retval`
loads also preserve their typed pointer or aggregate layouts across bindings,
so `let files = $ctx.arg0; $files.fdt.fd.f_inode.i_ino`,
`ctx.arg0.fdt.fd.0.f_inode.i_ino`, `let fd = $ctx.arg0.fdt.fd;
$fd.0.f_inode.i_ino`, `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx);
$fd.f_inode.i_ino`, and `let inode = $ctx.arg0.f_inode; $inode.i_sb.s_flags`
continue to type-check and lower as expected. 16-byte byte-array/string keys
such as `ctx.arg0.comm` continue to display as strings.
Aggregate `fexit` returns still depend on kernel trampoline support; some
kernels reject struct returns entirely.

## Commands

| Command | Description |
|---------|-------------|
| `ebpf attach` | Attach eBPF probe with closure |
| `ebpf detach` | Detach a probe by ID |
| `ebpf list` | List active probes |
| `ebpf counters` | Read counter map |
| `ebpf histogram` | Read histogram buckets |
| `ebpf stacks` | Read stack traces |
| `ebpf trace` | Read raw trace events |
| `ebpf setup` | Configure capabilities |

## Helper Commands (inside closures)

| Command | Description |
|---------|-------------|
| `emit` | Send value to userspace |
| `count` | Increment counter by key |
| `histogram` | Add value to log2 histogram |
| `start-timer` | Record start timestamp |
| `stop-timer` | Calculate elapsed time |
| `read-str` | Read string from user memory (`--max-len` to cap, default 128) |
| `read-kernel-str` | Read string from kernel memory (`--max-len` to cap, default 128) |

## Discovering Tracepoints

```bash
# List tracepoint categories
ls /sys/kernel/tracing/events/

# List syscall tracepoints
ls /sys/kernel/tracing/events/syscalls/

# View tracepoint fields
cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
```

## Limits

| Resource | Limit |
|----------|-------|
| eBPF stack | 512 bytes |
| String reads | 128 bytes max |
| Map entries | 10,240 per map |
| Ring buffer | 256 KB |
| Stack traces | 127 frames |

## License

MIT
