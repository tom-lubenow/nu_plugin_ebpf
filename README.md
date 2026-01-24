# nu_plugin_ebpf

A [Nushell](https://nushell.sh/) plugin that compiles Nushell closures to eBPF bytecode for kernel-level tracing and profiling.

## Features

- **Compile Nushell to eBPF**: Write tracing logic in familiar Nushell syntax
- **Multiple probe types**: kprobe, kretprobe, tracepoint, uprobe, uretprobe
- **Aggregations**: Count by key, histograms, timing measurements
- **Event streaming**: Real-time event output via ring buffers
- **Map sharing**: Share data between probes with `--pin`

## Requirements

- Linux kernel 4.18+ (for BPF ring buffers and CO-RE)
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

# Or run the setup command
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
| `arg0`-`arg5` | Function arguments | kprobe, uprobe |
| `retval` | Return value | kretprobe, uretprobe |

Tracepoint fields are read from `/sys/kernel/tracing/events/<category>/<name>/format`.

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
| `read-str` | Read string from user memory |
| `read-kernel-str` | Read string from kernel memory |

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
