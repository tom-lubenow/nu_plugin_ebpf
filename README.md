# nu_plugin_ebpf

A [Nushell](https://nushell.sh/) plugin that compiles Nushell closures to eBPF bytecode for kernel-level tracing and profiling.

## Features

- **Compile Nushell to eBPF**: Write tracing logic in familiar Nushell syntax
- **Multiple attach types**: kprobe, kretprobe, fentry, fexit, tracepoint, uprobe, uretprobe, xdp, tc
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

# Count loopback packets by packet length via XDP, then pass them through
let id = ebpf attach 'xdp:lo' {|ctx| $ctx.packet_len | count; 2 }

# Count packets at tc ingress on loopback
let id = ebpf attach 'tc:lo:ingress' {|ctx| $ctx.packet_len | count; 0 }
```

### Count syscalls by process

```nushell
# Attach probe (returns probe ID)
let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.comm | count }

# Let it run, then read counters
sleep 5sec
ebpf counters $id | sort-by count --reverse
```

### Reuse typed values through a named map

```nushell
let id = ebpf attach 'fentry:security_file_open' {|ctx|
    $ctx.arg0.f_path | map-put seen_paths $ctx.pid --kind hash
    let entry = ($ctx.pid | map-get seen_paths --kind hash)
    if $entry != 0 { $entry | count }
}

sleep 5sec
ebpf counters $id
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

Run the repeatable manual integration checks with the Nu harness in
`scripts/manual_integration.nu`. The script auto-selects the newest built plugin
from `target/debug/nu_plugin_ebpf` and `target/release/nu_plugin_ebpf` unless
`PLUGIN_BIN` is set.

```bash
cargo build
sudo nu ./scripts/manual_integration.nu
```

Override the plugin path if needed:

```bash
PLUGIN_BIN=/path/to/nu_plugin_ebpf sudo nu ./scripts/manual_integration.nu
```

If you want to test with a specific Nu build, run that binary directly:

```bash
sudo target/debug/nu ./scripts/manual_integration.nu
```

## Context Fields

The closure receives a context parameter with these fields:

| Field | Description | Probe Types |
|-------|-------------|-------------|
| `pid` | Thread ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `tgid` | Process ID (thread group) | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `uid` | User ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `gid` | Group ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `comm` | Process name (16 bytes) | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `cpu` | CPU ID | All |
| `ktime` | Kernel timestamp (ns) | All |
| `packet_len` | Packet length (`data_end - data` on XDP, `skb->len` on TC) | xdp, tc |
| `data` | Packet data pointer | xdp, tc |
| `data_end` | Packet end pointer | xdp, tc |
| `ingress_ifindex` | Ingress interface index | xdp, tc |
| `ifindex` | XDP ingress interface index alias | xdp |
| `rx_queue_index` | XDP receive queue index | xdp |
| `egress_ifindex` | XDP egress interface index | xdp |
| `arg0`-`argN` | Function arguments | kprobe, uprobe, fentry, fexit |
| `retval` | Return value | kretprobe, uretprobe, fexit |

Tracepoint fields are read from `/sys/kernel/tracing/events/<category>/<name>/format`.

`xdp` and `tc` both expose `ctx.cpu`, `ctx.ktime`, `ctx.packet_len`,
`ctx.ingress_ifindex`, and raw packet pointers `ctx.data` and `ctx.data_end`.
Scalar packet byte reads work through normal Nushell indexing such as
`($ctx.data | get 0)`, and fixed-width big-endian scalars can be read directly
through cell paths such as `$ctx.data.u16be.6` or `$ctx.data.u32be.0`. These
lower to data_end-guarded packet loads. Fixed header views `eth`, `ipv4`, `udp`,
and `tcp` are also available, for example `$ctx.data.eth.ethertype` or
`$ctx.data.eth.dst.0`. Those header views also support `payload` stepping:
`$ctx.data.eth.payload` skips Ethernet and a single VLAN tag when present,
`$ctx.data.eth.payload.ipv4.payload` skips a runtime-sized IPv4 header using
the IHL nibble, and `$ctx.data.eth.payload.ipv4.payload.tcp.payload` skips a
runtime-sized TCP header using the data offset. `xdp` additionally exposes `ctx.ifindex`,
`ctx.rx_queue_index`, and `ctx.egress_ifindex`. Variable header lengths, VLAN
options parsing, deeper TCP option parsing, stacked VLAN tags, and named
packet-program action helpers are still not modeled, so
XDP closures currently need to return an explicit numeric action code such as
`2` (`XDP_PASS`), and TC closures currently need to return an explicit numeric
classifier action code such as `0` (`TC_ACT_OK`).

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
($ctx.arg0.fdt.max_fds - 1); ... }`. Typed BTF bitfields can also be projected through the same paths, including
after numeric `get`, for example `let idx = ($ctx.pid mod 2); let clamp =
($ctx.arg0.uclamp_req | get $idx); $clamp.value`. Terminal array leaves and unsupported aggregate
leaves are exposed as stack-backed byte buffers, while representable terminal struct
leaves keep their field layouts, including BTF bitfield members, for
`count`/`ebpf counters`, and single-value `emit` can stream those struct
leaves as records. Nested array/record fields inside emitted values also
decode recursively when the compiler can preserve their layouts. `emit` still
preserves unsupported aggregate layouts as binary payloads, and `count`
supports them as byte-buffer keys. `ebpf counters`
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
Generic named maps are also available through `map-get`, `map-put`, and
`map-delete`. `map-get` returns a maybe-null map-value pointer. When a prior
typed `map-put` established the value layout in the same closure, projections
like `let entry = ($ctx.pid | map-get seen_paths --kind hash); if $entry != 0
{ $entry.dentry.d_flags }` lower through that preserved map-value schema, and
whole-value uses like `{ $entry | emit }` or `{ $entry | count }` preserve the
same typed aggregate layout instead of collapsing to a raw pointer scalar.
That preserved layout also survives record construction, so `if $entry != 0 {
{ path: $entry } | emit }` streams `path` as a nested record instead of a raw
pointer or opaque bytes. The same null-checked layout now also survives simple
user-defined function boundaries, so `def project-entry [entry] { $entry }`
can feed `if $entry != 0 { (project-entry $entry) | emit }` without collapsing
back to an untyped scalar. Call-site typed arguments now also specialize simple
user-defined functions, so callees can project typed fields directly from their
parameters, for example `def inode-flags [file] { $file.f_inode.i_flags }`.
When those looked-up aggregates are written back through `map-put`, the stored
value shape stays canonical too, so map-to-map copies preserve the real
aggregate layout instead of a pointer wrapper. When those maps are attached
with the same `--pin` group, active pinned programs now reuse that typed schema
across program boundaries too.
Generic map `--kind` now supports `hash`, `array`, `lru-hash`,
`per-cpu-hash`, `per-cpu-array`, and `lru-per-cpu-hash`.

Read-only closure captures now lower as real constants for supported types
(`int`, `bool`, `string`, and `nothing`) instead of only working when inlined
manually. That means existing Nushell structure can keep driving compile-time
positions such as generic map names, for example `let map_name = "seen_paths";
$ctx.arg0.f_path | map-put $map_name $ctx.pid --kind hash`. Reassigned captured
numeric scalars and representable constant records now take the next step and
lower as compiler-managed mutable globals backed by `.data` or `.bss`, so
ordinary Nushell variable flow can express per-program state without dropping
down to explicit maps for the smallest cases. That mutable-record path is
still intentionally honest: it works for values with a real byte layout, not
for metadata-only record builders that have never been materialized.

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
| `map-get` | Look up a value pointer in a named generic map |
| `map-put` | Insert or update a value in a named generic map |
| `map-delete` | Delete a key from a named generic map |

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
