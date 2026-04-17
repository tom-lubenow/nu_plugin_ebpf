# Example Gallery

Runnable snippets for the current attach surface. See the [README](../README.md) for installation and the short quick start, and see the [reference](reference.md) for detailed field and helper semantics.

> Safety: prefer `--dry-run` on the host when exploring new `struct_ops` objects, especially `sched_ext_ops`. Live `sched_ext` registration requires `--unsafe-struct-ops` and should be done in an isolated environment.

## Core Tracing

```nushell
# Stream PIDs calling sys_clone (Ctrl-C to stop)
ebpf attach --stream 'kprobe:sys_clone' {|ctx| $ctx.pid | emit }

# Capture first 10 sys_read calls
ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.tgid | emit } | first 10

# Capture first 10 fentry hits on ksys_read
ebpf attach -s 'fentry:ksys_read' {|ctx| $ctx.pid | emit } | first 10

# Capture the first file_open flags seen through a named BTF-backed arg
ebpf attach -s 'fentry:security_file_open' {|ctx| $ctx.arg.file.f_flags | emit } | first 1

# Capture openat2 flags from a pointer-backed trampoline arg
ebpf attach -s 'fentry:do_sys_openat2' {|ctx| $ctx.arg2.flags | emit } | first 1

# Capture the first ksys_read return value
ebpf attach -s 'fexit:ksys_read' {|ctx| $ctx.retval | emit } | first 1

# Count syscalls through a BTF-enabled raw tracepoint
ebpf attach 'tp_btf:sys_enter' {|ctx| $ctx.arg.regs.orig_ax | count; 0 }

# Dry-run an LSM file_open hook using BTF-backed hook arguments
ebpf attach --dry-run 'lsm:file_open' {|ctx| $ctx.arg.file.f_flags | count; 0 }

# Count software cpu-clock samples by CPU
let id = ebpf attach 'perf_event:software:cpu-clock:period=100000' {|ctx| $ctx.cpu | count; 0 }

# Count software cpu-clock samples by sampled pt_regs arg0 register
let id = ebpf attach 'perf_event:software:cpu-clock:period=100000' {|ctx| $ctx.arg0 | count; 0 }

# Count software cpu-clock samples by sampled period (x86_64)
let id = ebpf attach 'perf_event:software:cpu-clock:period=100000' {|ctx| $ctx.sample_period | count; 0 }

# Count syscalls by current cgroup ID
let id = ebpf attach 'kprobe:ksys_read' {|ctx| $ctx.cgroup_id | count }
```

## Packet And Socket Programs

```nushell
# Count loopback UDP packets by stable socket cookie on a bound socket_filter receive socket
let id = ebpf attach 'socket_filter:udp4:127.0.0.1:31337' {|ctx| $ctx.socket_cookie | count; 'pass' }

# Count loopback packets by socket owner UID on tc ingress
let id = ebpf attach 'tc:lo:ingress' {|ctx| $ctx.socket_uid | count; 'ok' }

# Count loopback UDPv6 packets by length on a bound socket_filter receive socket
let id = ebpf attach 'socket_filter:udp6:[::1]:31337' {|ctx| $ctx.packet_len | count; 'pass' }

# Count loopback TCP packets by length on a bound socket_filter listener
let id = ebpf attach 'socket_filter:tcp4:127.0.0.1:31337' {|ctx| $ctx.packet_len | count; 'pass' }

# Count sockmap verdict events by network-namespace cookie
let id = ebpf attach 'sk_msg:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.netns_cookie | count; 'pass' }

# Count loopback packets by packet length via XDP, then pass them through
let id = ebpf attach 'xdp:lo' {|ctx| $ctx.packet_len | count; 'pass' }

# Dry-run an XDP redirect-map program shape with an explicit redirect-map family
ebpf attach --dry-run 'xdp:lo' {|ctx| redirect-map demo_xsks $ctx.rx_queue_index --kind xskmap }

# Dry-run a plain XDP ifindex redirect with the first-class packet redirect surface
ebpf attach --dry-run 'xdp:lo' {|ctx| redirect 2 }

# Dry-run an sk_msg socket redirect with the first-class socket redirect surface
ebpf attach --dry-run 'sk_msg:/sys/fs/bpf/demo_sockhash' {|ctx| redirect-socket peer_sockhash $ctx.local_port --kind sockhash }

# Count packets at tc ingress on loopback
let id = ebpf attach 'tc:lo:ingress' {|ctx| $ctx.packet_len | count; 'ok' }

# Redirect tc ingress traffic to a peer device with the first-class packet redirect surface
let id = ebpf attach 'tc:lo:ingress' {|ctx| redirect --peer 2 }

# Count packets on cgroup egress traffic
let id = ebpf attach 'cgroup_skb:/sys/fs/cgroup:egress' {|ctx| $ctx.packet_len | count; 'allow' }

# Count device major numbers requested inside a cgroup
let id = ebpf attach 'cgroup_device:/sys/fs/cgroup' {|ctx| $ctx.major | count; 'allow' }

# Count sysctl reads versus writes inside a cgroup
let id = ebpf attach 'cgroup_sysctl:/sys/fs/cgroup' {|ctx| $ctx.write | count; 'allow' }

# Count socket families at cgroup socket-create time
let id = ebpf attach 'cgroup_sock:/sys/fs/cgroup:sock_create' {|ctx| $ctx.family | count; 'allow' }

# Count sock_ops callback opcodes inside a cgroup
let id = ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| $ctx.op | count; 1 }

# Inspect the first sock_ops argument word through the normal fixed-array path
let id = ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| ($ctx.args | get 0) | count; 1 }

# Project the current sock_ops socket through the typed bpf_sock view
let id = ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| $ctx.sk.family | count; 1 }

# Write the raw sock_ops reply word through ordinary assignment
let id = ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| mut ctx = $ctx; $ctx.reply = 1; $ctx.op | count; 1 }

# Count current TCP congestion-window observations on loopback socket events
let id = ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| $ctx.snd_cwnd | count; 1 }

# Count sock_ops TCP progress counters on loopback socket events
let id = ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| ($ctx.snd_nxt + $ctx.bytes_acked + $ctx.mss_cache + $ctx.segs_out) | count; 1 }

# Count sock_ops packet-length observations when packet metadata is available
let id = ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| $ctx.skb_len | count; 1 }

# Count first-byte observations from packet-aware sock_ops callbacks
let id = ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| ($ctx.data | get 0) | count; 1 }

# Count first-byte observations on a pinned sockmap or sockhash sk_msg hook
let id = ebpf attach 'sk_msg:/sys/fs/bpf/demo_sockmap' {|ctx| ($ctx.data | get 0) | count; 'pass' }

# Project the current sk_msg socket through the typed bpf_sock view
let id = ebpf attach 'sk_msg:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.sk.family | count; 'pass' }

# Count sk_msg socket source ports through the typed bpf_sock view
let id = ebpf attach 'sk_msg:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.sk.src_port | count; 'pass' }

# Count local ports on a pinned sockmap or sockhash sk_skb stream-verdict hook
let id = ebpf attach 'sk_skb:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.local_port | count; 'pass' }

# Redirect sk_skb traffic through a named sockmap with the first-class socket redirect surface
let id = ebpf attach 'sk_skb:/sys/fs/bpf/demo_sockmap' {|ctx| redirect-socket peer_sockmap $ctx.local_port --kind sockmap }

# Count local ports on a pinned sockmap or sockhash sk_skb stream-parser hook
let id = ebpf attach 'sk_skb_parser:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.local_port | count; 0 }

# Project the current cgroup_sockopt socket through the typed bpf_sock view
let id = ebpf attach 'cgroup_sockopt:/sys/fs/cgroup:get' {|ctx| $ctx.sk.family | count; 'allow' }

# Inspect the first byte of the getsockopt buffer through ctx.optval
let id = ebpf attach 'cgroup_sockopt:/sys/fs/cgroup:get' {|ctx| ($ctx.optval | get 0) | count; 'allow' }

# Override the getsockopt return value through ordinary assignment
let id = ebpf attach 'cgroup_sockopt:/sys/fs/cgroup:get' {|ctx| mut ctx = $ctx; $ctx.sockopt_retval = 0; 'allow' }

# Count requested ports on cgroup connect4 hooks
let id = ebpf attach 'cgroup_sock_addr:/sys/fs/cgroup:connect4' {|ctx| $ctx.user_port | count; 'allow' }

# Project the current cgroup_sock_addr socket through the typed bpf_sock view
let id = ebpf attach 'cgroup_sock_addr:/sys/fs/cgroup:connect4' {|ctx| $ctx.sk.family | count; 'allow' }

# Inspect the last host-order IPv6 word on cgroup connect6 hooks
let id = ebpf attach 'cgroup_sock_addr:/sys/fs/cgroup:connect6' {|ctx| ($ctx.user_ip6 | get 3) | count; 'allow' }

# Count socket-lookup hits by local destination port in the current netns
let id = ebpf attach 'sk_lookup:/proc/self/ns/net' {|ctx| $ctx.local_port | count; 'pass' }

# Count socket-lookup hits by lookup cookie in the current netns
let id = ebpf attach 'sk_lookup:/proc/self/ns/net' {|ctx| $ctx.cookie | count; 'pass' }
```

## Struct Ops

```nushell
# Build a struct_ops object from constant value fields and optional callback closures.
# sched_ext_ops only requires a non-empty valid BPF object name using only
# [A-Za-z0-9_.]. Additional callbacks are optional. If you set `flags`,
# the bitmask is validated against the kernel's `scx_ops_flags` definitions.
# `timeout_ms` is also checked against the documented 30000ms maximum. If you
# implement `update_idle`, you must also implement `select_cpu` unless you set
# `SCX_OPS_KEEP_BUILTIN_IDLE`. That same flag keeps built-in idle-selection
# kfuncs like `scx_bpf_select_cpu_dfl`, `scx_bpf_select_cpu_and`, and
# `scx_bpf_pick_idle_cpu*` available. If you set
# `SCX_OPS_BUILTIN_IDLE_PER_NODE`, use `scx_bpf_pick_idle_cpu_node` instead of
# `scx_bpf_pick_idle_cpu` / `scx_bpf_pick_any_cpu`, and keep built-in idle
# tracking enabled. `SCX_OPS_ENQ_LAST` also requires an `enqueue` callback.
# Other scalar value members are range-checked against their kernel BTF field
# widths.
ebpf attach --dry-run 'struct_ops:sched_ext_ops' {
    name: 'nu_demo'
}

# Kernel-BTF-backed contexts also expose named parameters through
# ctx.arg.<name>. This includes sched_ext callbacks, LSM hooks, and
# fentry/fexit targets with BTF names. This dry-run example shows the safe
# sched_ext cpumask acquire/use/release pattern:
# acquire a referenced cpumask, null-check it, use it, and always release it.
ebpf attach --dry-run 'struct_ops:sched_ext_ops' {
    name: 'nu_demo'
    select_cpu: {|ctx|
        let p = $ctx.arg.p
        let prev = $ctx.arg.prev_cpu
        let wake = $ctx.arg.wake_flags
        let mask = (kfunc-call 'scx_bpf_get_online_cpumask')
        if $mask != 0 {
            let cpu = (kfunc-call 'scx_bpf_select_cpu_and' $p $prev $wake $mask 0)
            kfunc-call 'scx_bpf_put_cpumask' $mask
            $cpu
        } else {
            $prev
        }
    }
}

# Live sched_ext registration is gated behind an explicit opt-in because a buggy
# scheduler can make the host unstable. Prefer dry-run on the host and use a VM
# or disposable environment for real sched_ext loads.
# ebpf attach --unsafe-struct-ops 'struct_ops:sched_ext_ops' {
#     name: 'nu_demo'
#     select_cpu: {|ctx| 0 }
# }

# Safer live struct_ops families can be loaded directly. This minimal
# tcp_congestion_ops example registers and can then be detached again.
# The kernel requires a non-empty name that fits the fixed field plus
# callback closures for ssthresh, cong_avoid, and undo_cwnd.
let id = ebpf attach 'struct_ops:tcp_congestion_ops' {
    name: 'nu_demo'
    ssthresh: {|ctx| 2 }
    undo_cwnd: {|ctx| 2 }
    cong_avoid: {|ctx| 0 }
}
ebpf detach $id

# Fixed integer-array value members can be initialized from constant int lists
# when the underlying struct_ops field uses an integer element type.
# Nested record values are also supported for by-value substruct members.
# Nested list values are also supported for by-value array members, including
# arrays of records.
# Initializers that would cross a pointer hop are still rejected.
```

## Recipes

### Count Syscalls By Process

```nushell
let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.comm | count }

sleep 5sec
ebpf counters $id | sort-by count --reverse
```

### Reuse Typed Values Through A Named Map

```nushell
let id = ebpf attach 'fentry:security_file_open' {|ctx|
    $ctx.arg.file.f_path | map-put seen_paths $ctx.pid --kind hash
    let entry = ($ctx.pid | map-get seen_paths --kind hash)
    if $entry != 0 { $entry | count }
}

sleep 5sec
ebpf counters $id
```

### Measure Function Latency

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

### Trace File Opens With Filenames

```nushell
ebpf attach -s 'tracepoint:syscalls/sys_enter_openat' {|ctx|
    { pid: $ctx.pid, file: ($ctx.filename | read-str) } | emit
}
```
