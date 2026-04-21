# Language And Context Reference

Detailed reference for the current compiler surface. See the [README](../README.md) for the front-page guide and the [example gallery](examples.md) for runnable snippets.

## Context Fields

The closure receives a context parameter with these fields:

| Field | Description | Probe Types |
|-------|-------------|-------------|
| `pid` | Kernel PID / thread ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `tid` | Alias for `pid` | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `tgid` | Process ID (thread group) | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `uid` | User ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `gid` | Group ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `comm` | Process name (16 bytes) | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `task` | Current `task_struct *` pointer from `bpf_get_current_task_btf`; BTF-backed fields such as `task.pid` can be projected when kernel BTF is available | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe, lsm, perf_event |
| `cgroup_id` | Current task cgroup ID | all current program types |
| `cpu` | CPU ID | All |
| `ktime` | Kernel timestamp (ns) | All |
| `sample_period` | Sample period from `bpf_perf_event_data` | perf_event (x86_64 currently) |
| `addr` | Sampled address from `bpf_perf_event_data` | perf_event (x86_64 currently) |
| `packet_len` | Packet length (`data_end - data` on XDP, `skb->len` on skb-backed packet programs, `size` on sk_msg, `skb_len` on packet-aware sock_ops callbacks) | xdp, socket_filter, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `pkt_type` | skb pkt_type | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `queue_mapping` | skb queue_mapping | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `eth_protocol` | skb protocol / ethertype in host byte order | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `vlan_present` | Whether skb VLAN metadata is present | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `vlan_tci` | skb VLAN TCI | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `vlan_proto` | skb VLAN ethertype in host byte order | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `cb` | skb control-block words as five host-order `u32` values | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `tc_classid` | skb tc_classid | tc |
| `napi_id` | skb napi_id | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `wire_len` | skb wire_len | tc |
| `gso_segs` | skb GSO segment count | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `gso_size` | skb GSO segment size | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `tstamp` | skb timestamp | tc, cgroup_skb |
| `tstamp_type` | skb timestamp type (`0 = UNSPEC`, `1 = DELIVERY_MONO`) | tc |
| `hwtstamp` | skb hardware timestamp | tc, cgroup_skb |
| `data` | Packet data pointer | xdp, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `data_meta` | Packet metadata pointer | xdp, tc |
| `data_end` | Packet end pointer | xdp, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `ingress_ifindex` | Ingress interface index | xdp, socket_filter, tc, cgroup_skb, sk_lookup, sk_skb, sk_skb_parser |
| `access_type` | Encoded cgroup device access type | cgroup_device |
| `major` | Requested device major number | cgroup_device |
| `minor` | Requested device minor number | cgroup_device |
| `ifindex` | Interface index (`xdp_md.ingress_ifindex` on XDP, `__sk_buff.ifindex` on skb-backed packet programs) | xdp, socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `tc_index` | skb tc_index | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `hash` | skb hash | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `socket_cookie` | Stable kernel socket cookie, or `0` when an skb has no known socket | socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_skb, sk_skb_parser, sock_ops |
| `socket_uid` | Owner UID of the socket associated with the current skb | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `netns_cookie` | Stable kernel network-namespace cookie | socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, sock_ops |
| `rx_queue_index` | XDP receive queue index | xdp |
| `egress_ifindex` | XDP egress interface index | xdp |
| `user_family` | Userspace-requested socket family | cgroup_sock_addr |
| `user_ip4` | IPv4 destination/source address in host byte order | cgroup_sock_addr (*4 hooks) |
| `user_ip6` | IPv6 address as four host-order `u32` words | cgroup_sock_addr (*6 hooks) |
| `user_port` | Requested port in host byte order | cgroup_sock_addr |
| `family` | Kernel socket family | cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `sock_type` | Socket type | cgroup_sock, cgroup_sock_addr |
| `protocol` | Socket protocol | cgroup_sock, cgroup_sock_addr, sk_lookup |
| `bound_dev_if` | Bound device ifindex | cgroup_sock (sock_create, sock_release) |
| `mark` | Socket or skb mark | cgroup_sock (sock_create, sock_release), socket_filter, tc, cgroup_skb |
| `priority` | Socket or skb priority | cgroup_sock (sock_create, sock_release), socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `state` | Current socket or TCP state | cgroup_sock, sock_ops |
| `op` | sock_ops callback opcode | sock_ops |
| `args` | sock_ops callback argument words as four host-order `u32` values | sock_ops |
| `is_fullsock` | Whether the context has a full socket | sock_ops |
| `snd_cwnd` | Current sending congestion window | sock_ops |
| `srtt_us` | Smoothed RTT in microseconds shifted by 3 | sock_ops |
| `cb_flags` | Requested sock_ops callback flags | sock_ops |
| `state` | Current TCP state | sock_ops |
| `rtt_min` | Minimum observed RTT in microseconds | sock_ops |
| `snd_ssthresh` | Current slow-start threshold | sock_ops |
| `rcv_nxt` | Next expected receive sequence number | sock_ops |
| `snd_nxt` | Next send sequence number | sock_ops |
| `snd_una` | Oldest unacknowledged send sequence number | sock_ops |
| `mss_cache` | Current cached MSS | sock_ops |
| `ecn_flags` | Current ECN/TCP option flags | sock_ops |
| `rate_delivered` | Recently delivered packet count used for rate sampling | sock_ops |
| `rate_interval_us` | Delivery-rate sampling interval in microseconds | sock_ops |
| `packets_out` | Number of outstanding packets | sock_ops |
| `retrans_out` | Number of retransmitted outstanding packets | sock_ops |
| `total_retrans` | Total retransmission count | sock_ops |
| `segs_in` | Total inbound segment count | sock_ops |
| `data_segs_in` | Total inbound data-segment count | sock_ops |
| `segs_out` | Total outbound segment count | sock_ops |
| `data_segs_out` | Total outbound data-segment count | sock_ops |
| `lost_out` | Current lost-out packet estimate | sock_ops |
| `sacked_out` | Current SACKed-out packet estimate | sock_ops |
| `sk_txhash` | Socket transmit hash | sock_ops |
| `bytes_received` | Total received byte count | sock_ops |
| `bytes_acked` | Total acknowledged byte count | sock_ops |
| `skb_len` | Total packet length when packet metadata is available | sock_ops |
| `skb_tcp_flags` | Packet TCP flags when packet metadata is available | sock_ops |
| `skb_hwtstamp` | Packet hardware timestamp when packet metadata is available | sock_ops |
| `msg_src_ip4` | IPv4 source address in host byte order | cgroup_sock_addr (sendmsg4) |
| `msg_src_ip6` | IPv6 source address as four host-order `u32` words | cgroup_sock_addr (sendmsg6) |
| `remote_ip4` | Remote IPv4 address in host byte order | cgroup_sock, cgroup_sock_addr (connect4, getpeername4, sendmsg4, recvmsg4), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `remote_ip6` | Remote IPv6 address as four host-order `u32` words | cgroup_sock, cgroup_sock_addr (connect6, getpeername6, sendmsg6, recvmsg6), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `remote_port` | Remote port in host byte order | cgroup_sock, cgroup_sock_addr (connect4, connect6, getpeername4, getpeername6, sendmsg4, sendmsg6, recvmsg4, recvmsg6), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_ip4` | Local IPv4 address in host byte order | cgroup_sock (post_bind4), cgroup_sock_addr (bind4, getsockname4, sendmsg4), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_ip6` | Local IPv6 address as four host-order `u32` words | cgroup_sock (post_bind6), cgroup_sock_addr (bind6, getsockname6, sendmsg6), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_port` | Local port in host byte order | cgroup_sock (post_bind4, post_bind6), cgroup_sock_addr (bind4/bind6, getsockname4/getsockname6), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `rx_queue_mapping` | Socket receive-queue mapping (`-1` if unset) | cgroup_sock |
| `sk` | Typed `bpf_sock *` pointer for socket projection such as `$ctx.sk.family` or `$ctx.sk.bound_dev_if`; currently exposes `bound_dev_if`, `family`, `type`, `protocol`, `mark`, `priority`, `src_ip4`, `src_ip6`, `src_port`, `dst_port` (raw network byte order), `dst_ip4`, `dst_ip6`, `state`, and `rx_queue_mapping` | socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `cookie` | Socket lookup cookie | sk_lookup |
| `level` | Socket-option level | cgroup_sockopt |
| `optname` | Socket-option name | cgroup_sockopt |
| `optlen` | Socket-option length | cgroup_sockopt |
| `optval` | Kernel pointer to the sockopt buffer | cgroup_sockopt |
| `optval_end` | Kernel pointer to the end of the sockopt buffer | cgroup_sockopt |
| `sockopt_retval` | Getsockopt return value on `get` hooks | cgroup_sockopt |
| `arg0`-`argN` | Function arguments or raw sampled ABI register slots; kernel-BTF-backed contexts also expose named `ctx.arg.<name>` aliases when kernel BTF includes names | kprobe, uprobe, fentry, fexit, tp_btf, lsm, struct_ops, raw_tracepoint, perf_event |
| `retval` | Return value | kretprobe, uretprobe, fexit |

Tracepoint fields are read from `/sys/kernel/tracing/events/<category>/<name>/format`.

## Program-Family Notes

`xdp`, `tc`, and `cgroup_skb` expose `ctx.cpu`, `ctx.ktime`,
`ctx.packet_len`, `ctx.ingress_ifindex`, `ctx.ifindex`, and raw
packet pointers `ctx.data` / `ctx.data_end`. `sk_msg`, `sk_skb`, and
`sk_skb_parser` also expose `ctx.data` / `ctx.data_end` on their
message or skb contexts. `socket_filter` keeps `ctx.cpu`,
`ctx.ktime`, `ctx.packet_len`, `ctx.ingress_ifindex`, and `ctx.ifindex`,
but it does not expose raw packet pointers. Scalar packet byte reads
work through normal Nushell indexing such as `($ctx.data | get 0)`,
and fixed-width big-endian scalars can be read directly through cell
paths such as `$ctx.data.u16be.6` or `$ctx.data.u32be.0`. These lower
to data_end-guarded packet loads. On `xdp`, `tc`, `sk_skb`, and `sk_skb_parser`, the same scalar/header
packet paths are also writable through ordinary cell-path updates
after shadowing the immutable closure parameter as mutable, for
example `mut ctx = $ctx; $ctx.data.0 = 0xff`, `mut ctx = $ctx;
$ctx.data.u16be.6 = 0x86dd`, or `mut ctx = $ctx;
$ctx.data.eth.ethertype = 0x86dd`. Those lower to guarded packet
stores and automatically normalize big-endian packet scalars back to
network byte order. Other packet families remain read-only for direct
packet writes. Fixed header views `eth`, `ipv4`, `ipv6`, `icmp`,
`icmpv6`, `udp`, and `tcp` are also available, for example
`$ctx.data.eth.ethertype`, `$ctx.data.eth.payload.ipv4.protocol`,
`$ctx.data.eth.payload.ipv6.next_header`,
`$ctx.data.eth.payload.ipv4.payload.icmp.type`, or
`$ctx.data.eth.payload.ipv6.payload.icmpv6.code`. Nested
protocol-following views reuse the same runtime packet stepping as
explicit `.payload`, so forms like `$ctx.data.eth.ipv4.tcp.seq` and
`$ctx.data.eth.ipv6.udp.src` also skip stacked VLAN tags, runtime-sized
IPv4 headers, and the bounded common IPv6 extension-header chain
automatically. Those header views also support `payload` stepping:
`$ctx.data.eth.payload` skips Ethernet and up to two stacked VLAN tags
when present, `$ctx.data.eth.payload.ipv4.payload` skips a runtime-sized
IPv4 header using the IHL nibble, `$ctx.data.eth.payload.ipv6.payload`
skips the fixed 40-byte IPv6 header plus a bounded chain of common
IPv6 extension headers (`hop-by-hop`, `routing`, `fragment`, `auth`,
and `destination options`), `$ctx.data.eth.payload.ipv4.payload.icmp.payload`
and `$ctx.data.eth.payload.ipv6.payload.icmpv6.payload` skip the fixed
8-byte ICMP header, and `$ctx.data.eth.payload.ipv4.payload.tcp.payload`
skips a runtime-sized TCP header using the data offset. `xdp`
additionally exposes `ctx.data_meta`, `ctx.ifindex`,
`ctx.rx_queue_index`, and `ctx.egress_ifindex`. `ctx.data_meta` is a
packet-metadata pointer: scalar reads such as `($ctx.data_meta | get 0)`
use the same packet address space as `ctx.data`, but they are guarded
against `ctx.data` rather than `ctx.data_end`. `tc` also exposes
`ctx.data_meta` with the same `ctx.data`-guarded packet semantics,
which is useful for consuming metadata carried forward from earlier
packet-processing stages. `adjust-packet --head|--meta|--tail DELTA`
is the preferred first-class XDP relayout surface; it lowers to
`bpf_xdp_adjust_head`, `bpf_xdp_adjust_meta`, or `bpf_xdp_adjust_tail`
and materializes the XDP context pointer automatically. On `tc`,
`sk_skb`, and `sk_skb_parser`, `adjust-packet --head|--tail DELTA`,
`adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]`
are the preferred first-class skb relayout surfaces, lowering to
`bpf_skb_change_head`, `bpf_skb_change_tail`, `bpf_skb_pull_data`,
and `bpf_skb_adjust_room` with the ambient skb context pointer
materialized automatically. After XDP adjust helpers, previously
loaded packet pointers are invalid and must be reloaded from
`ctx.data`, `ctx.data_meta`, and `ctx.data_end` before further packet
access. After skb relayout helpers, reload `ctx.data` and
`ctx.data_end` before further packet access. The raw
`helper-call "bpf_xdp_adjust_*" $ctx DELTA` and `helper-call "bpf_skb_*" ...`
forms are still modeled when you need the escape hatch. `tc`,
`sk_skb`, and `sk_skb_parser` also model skb packet-edit helpers
through the ordinary helper surface, including `bpf_skb_store_bytes`,
`bpf_l3_csum_replace`, `bpf_l4_csum_replace`,
`bpf_get_hash_recalc`, `bpf_csum_update`, and
`bpf_set_hash_invalid`. The skb-backed packet contexts
(`socket_filter`, `tc`, `cgroup_skb`, `sk_skb`, and `sk_skb_parser`)
also expose `ctx.sk` for typed `bpf_sock` projection such as
`$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, or
`$ctx.sk.mark`, plus common skb metadata `ctx.pkt_type`,
`ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`,
`ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.napi_id`,
`ctx.gso_segs`, `ctx.gso_size`, `ctx.tc_index`, and `ctx.hash`.
Additional metadata is family-specific: `ctx.tc_classid`,
`ctx.wire_len`, and `ctx.tstamp_type` are tc-only; `ctx.tstamp` and
`ctx.hwtstamp` are available on tc and cgroup_skb; `ctx.mark` is
available on cgroup_sock `sock_create` / `sock_release`, socket_filter,
tc, and cgroup_skb; and `ctx.priority` is available on cgroup_sock
`sock_create` / `sock_release` and across the skb-backed packet
families. `cgroup_skb`, `sk_skb`, and `sk_skb_parser` also
expose direct socket-common and tuple aliases (`ctx.family`,
`ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`,
`ctx.local_ip6`, `ctx.local_port`) from the ambient `__sk_buff`
context; the IPv4 address and remote-port fields are normalized to
host byte order, and the IPv6 fields stay fixed arrays of four
host-order `u32` words. `ctx.eth_protocol` and `ctx.vlan_proto` are
normalized to host byte order, and `ctx.cb` follows the same
fixed-array model as `ctx.args`. Writable skb
metadata is attach-sensitive. On `socket_filter`, fixed `ctx.cb.N`
is writable. On `tc`, `ctx.mark`, `ctx.priority`, `ctx.tc_index`,
`ctx.tc_classid`, fixed `ctx.cb.N`, and `ctx.tstamp` are writable.
On `cgroup_skb`, `ctx.mark`, `ctx.priority`, and fixed `ctx.cb.N`
are writable on both directions, and `ctx.tstamp` is additionally
writable on `:egress`. On `sk_skb` and `sk_skb_parser`,
`ctx.priority` and `ctx.tc_index` are writable. These all use
ordinary assignment after shadowing the closure parameter as mutable,
for example `mut ctx = $ctx; $ctx.mark = 7`, `mut ctx = $ctx;
$ctx.cb.0 = 1`, `mut ctx = $ctx; $ctx.priority = 3`, `mut ctx = $ctx;
$ctx.tc_index = 5`, or `mut ctx = $ctx; $ctx.tstamp = 123`. Other
skb-backed metadata fields remain read-only on the remaining hooks.
When the timestamp type must also change, `tc` additionally models
`helper-call "bpf_skb_set_tstamp" $ctx TSTAMP TSTAMP_TYPE`; the
current kernel UAPI uses `0` for `BPF_SKB_TSTAMP_UNSPEC` and `1` for
`BPF_SKB_TSTAMP_DELIVERY_MONO`. The initial `socket_filter` surface
uses targets like `socket_filter:udp4:127.0.0.1:31337`,
`socket_filter:udp6:[::1]:31337`, `socket_filter:tcp4:127.0.0.1:31337`,
and `socket_filter:tcp6:[::1]:31337`, which create and keep open a
bound socket while attached. `socket_filter` return values are
snapshot lengths: return `0` to drop the packet or a positive value to
keep it, and aliases like `"pass"` / `"keep"` expand to
`ctx.packet_len`. Variable header lengths, VLAN options parsing,
deeper TCP option parsing, ICMP subtype-specific body decoding,
uncommon IPv6 extension headers, and named packet-program action
helpers are still not modeled, but compile-time action aliases are
available in return position. XDP closures can return strings like
`"pass"` / `"drop"`, and TC closures can return strings like `"ok"` /
`"shot"`. Raw numeric return codes still work. `redirect IFINDEX` is
the preferred first-class surface for `bpf_redirect` on XDP and tc,
and `redirect --flags N IFINDEX` exposes the helper flags argument
directly; XDP still requires `FLAGS = 0`. On `tc:...:ingress`,
`redirect --peer IFINDEX` is the preferred first-class surface for
`bpf_redirect_peer` and still requires `FLAGS = 0`. On tc,
`redirect --neigh IFINDEX` is the preferred first-class surface for
the default-neighbor form of `bpf_redirect_neigh`, lowering to
`bpf_redirect_neigh(IFINDEX, 0, 0, FLAGS)`; `FLAGS` must also stay
`0`. The raw `helper-call "bpf_redirect*" ...` forms are still
modeled when you need the escape hatch.

On XDP, `adjust-packet --head|--meta|--tail DELTA` is the preferred first-class surface for packet relayout. It selects the corresponding `bpf_xdp_adjust_*` helper, materializes the ambient context pointer automatically, and returns the helper result directly. On `tc`, `sk_skb`, and `sk_skb_parser`, `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` do the same for `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room`.

On XDP and tc, `redirect IFINDEX` is the preferred first-class surface for packet redirection. `redirect --peer IFINDEX` selects `bpf_redirect_peer` on `tc:...:ingress`, and `redirect --neigh IFINDEX` selects the default-neighbor form of `bpf_redirect_neigh` on tc. All three forms return the helper result directly so a closure can end with `redirect ...`.

On XDP, `redirect-map MAP KEY --kind devmap|devmap-hash|cpumap|xskmap` is the preferred first-class surface for `bpf_redirect_map`. It returns the helper result directly, so a closure can end with `redirect-map ...` instead of spelling the helper name through `helper-call`.

On `sk_msg`, `sk_skb`, and `sk_skb_parser`, `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class surface for the socket redirect helpers. It picks `bpf_msg_redirect_{map,hash}` or `bpf_sk_redirect_{map,hash}` from the current program type, materializes the ambient context pointer automatically, and returns the helper result directly so a closure can end with `redirect-socket ...`.

Local-storage helpers use the ordinary modeled `helper-call` escape hatch, but the map kind is fixed by the helper. Passing a literal map name as arg0 to `bpf_sk_storage_{get,delete}`, `bpf_inode_storage_{get,delete}`, `bpf_task_storage_{get,delete}`, or `bpf_cgrp_storage_{get,delete}` materializes a `sk_storage`, `inode_storage`, `task_storage`, or `cgrp_storage` map FD respectively; no `--kind` argument is required or accepted for these helpers. For `*_storage_get`, a typed non-null init value in arg2 also seeds the storage map value layout used for the emitted map definition.

`perf_event` currently supports software `cpu-clock`, `task-clock`, `context-switches`, `cpu-migrations`, `page-faults`, `minor-faults`, and `major-faults`, plus hardware `cpu-cycles`, `instructions`, `cache-references`, `cache-misses`, `branch-instructions`, `branch-misses`, `bus-cycles`, `stalled-cycles-frontend`, `stalled-cycles-backend`, and `ref-cpu-cycles` through specs like `perf_event:software:cpu-clock` or `perf_event:hardware:cpu-cycles`. Optional selectors `cpu=N`, `pid=N`, `period=N`, and `freq=N` are supported; omitting the sample policy defaults to `period=1000000`, and omitting `cpu=` attaches on all online CPUs. `pid=N` scopes the event to a single process, and it can be combined with `cpu=N` for one-process/one-cpu sampling. The current surface uses the ordinary helper-backed fields like `ctx.pid`, `ctx.comm`, `ctx.cpu`, and `ctx.ktime`; it also reuses `ctx.arg0`-`ctx.arg5` as raw sampled pt_regs register slots, and on x86_64 builds it exposes the raw `bpf_perf_event_data` fields `ctx.sample_period` and `ctx.addr`. The `ctx.argN` values here are sampled register snapshots, not named BTF-backed function arguments.

`cgroup_sysctl` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.write`, and `ctx.file_pos`, and closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes. `ctx.file_pos` is also writable through ordinary assignment after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.file_pos = 0`, while `ctx.write` remains read-only. Modeled sysctl helpers are available through the ordinary helper surface: `bpf_sysctl_get_name`, `bpf_sysctl_get_current_value`, `bpf_sysctl_get_new_value`, and `bpf_sysctl_set_new_value`. The kernel keeps their usual runtime semantics here: `bpf_sysctl_get_new_value` and `bpf_sysctl_set_new_value` return `-EINVAL` on read contexts, and `bpf_sysctl_get_name` uses `BPF_F_SYSCTL_BASE_NAME` for base-name-only mode.

`cgroup_sock` currently supports `sock_create`, `sock_release`, `post_bind4`, and `post_bind6`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.family`, `ctx.sock_type`, `ctx.protocol`, `ctx.state`, `ctx.rx_queue_mapping`, `ctx.socket_cookie`, `ctx.netns_cookie`, `ctx.remote_ip4`, `ctx.remote_ip6`, and `ctx.remote_port` on every supported hook. Direct `ctx.bound_dev_if`, `ctx.mark`, and `ctx.priority` are only available on `sock_create` / `sock_release`, matching the current upstream verifier surface more closely, and ordinary assignment is supported there after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.mark = 7`. Direct `ctx.local_ip4` is available on `post_bind4`, `ctx.local_ip6` on `post_bind6`, and `ctx.local_port` on both post-bind hooks. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. On `cgroup_sock`, the source-side projection members follow the same attach-sensitive policy as the direct locals: `$ctx.sk.src_ip4` is only available on `post_bind4`, `$ctx.sk.src_ip6` on `post_bind6`, and `$ctx.sk.src_port` on both post-bind hooks. Destination-side projections such as `$ctx.sk.dst_port` remain available on every hook.

`cgroup_device` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.access_type`, `ctx.major`, and `ctx.minor`, and closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes. `ctx.access_type` is the raw kernel encoding `(BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*`.

`sock_ops` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes the sock_ops callback opcode and argument words (`ctx.op`, `ctx.args`), the socket tuple and metadata fields (`ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, `ctx.socket_cookie`, `ctx.netns_cookie`), the TCP/congestion and progress counters (`ctx.is_fullsock`, `ctx.snd_cwnd`, `ctx.srtt_us`, `ctx.cb_flags`, `ctx.state`, `ctx.rtt_min`, `ctx.snd_ssthresh`, `ctx.rcv_nxt`, `ctx.snd_nxt`, `ctx.snd_una`, `ctx.mss_cache`, `ctx.ecn_flags`, `ctx.rate_delivered`, `ctx.rate_interval_us`, `ctx.packets_out`, `ctx.retrans_out`, `ctx.total_retrans`, `ctx.segs_in`, `ctx.data_segs_in`, `ctx.segs_out`, `ctx.data_segs_out`, `ctx.lost_out`, `ctx.sacked_out`, `ctx.sk_txhash`, `ctx.bytes_received`, and `ctx.bytes_acked`), plus packet-metadata fields `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.skb_len`, `ctx.skb_tcp_flags`, and `ctx.skb_hwtstamp` when the callback context has packet data available. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and remote port fields are normalized to host byte order. The IPv6 fields are exposed as fixed arrays of four host-order `u32` words, so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `ctx.reply`, `ctx.replylong.<0-3>`, and `ctx.sk_txhash` are writable raw `u32` words and can be assigned with ordinary Nushell cell-path updates after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.reply = 1`, `mut ctx = $ctx; $ctx.replylong.0 = 7`, or `mut ctx = $ctx; $ctx.sk_txhash = 7`. Packet-aware callbacks use the same guarded packet-access model as XDP and tc, and the verifier now requires a proven packet-aware `ctx.op` branch before loading those packet fields. Modeled sock_ops helpers are also available through the ordinary helper surface, including `bpf_getsockopt`, `bpf_setsockopt`, `bpf_sock_ops_cb_flags_set`, `bpf_load_hdr_opt`, `bpf_store_hdr_opt`, and `bpf_reserve_hdr_opt`. Those helpers still follow the kernel's ordinary callback-sensitive runtime rules, so unsupported `ctx.op` combinations can return `-EPERM`; the finer flag-sensitive `bpf_load_hdr_opt` subcases still remain kernel-enforced. sock_ops uses raw integer return codes; observation-only examples should return `1`.

`cgroup_sockopt` currently attaches to `get` and `set` cgroup socket-option hooks such as `/sys/fs/cgroup:get` or `/sys/fs/cgroup:set`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.level`, `ctx.optname`, `ctx.optlen`, `ctx.optval`, `ctx.optval_end`, `ctx.netns_cookie`, and `ctx.sockopt_retval` on `get` hooks, plus a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. `optval` / `optval_end` are surfaced as kernel pointers, so ordinary pointer reads like `($ctx.optval | get 0)` or `read-kernel-str` can inspect the buffer. Ordinary assignment now also covers the writable scalar surfaces the kernel exposes here: `ctx.sockopt_retval` on `cgroup_sockopt:get`, `ctx.level` / `ctx.optname` on `cgroup_sockopt:set`, `ctx.optlen` on either hook, and fixed-index sockopt-buffer rewrites such as `mut ctx = $ctx; $ctx.optval.0 = 1`. Modeled socket-option helpers are also available through the ordinary helper surface here, including `bpf_getsockopt` and `bpf_setsockopt` on the current sockopt context. Closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes.

`cgroup_sock_addr` currently exposes `ctx.cpu`, `ctx.ktime`, `ctx.socket_cookie`, `ctx.netns_cookie`, `ctx.user_family`, `ctx.user_ip4`, `ctx.user_ip6`, `ctx.user_port`, `ctx.family`, `ctx.sock_type`, `ctx.protocol`, plus `ctx.msg_src_ip4` on `sendmsg4` and `ctx.msg_src_ip6` on `sendmsg6`. It also normalizes the attach-sensitive hooks onto the ordinary tuple surface where the kernel semantics are clear: `connect*`, `getpeername*`, `sendmsg*`, and `recvmsg*` expose `ctx.remote_ip4`, `ctx.remote_ip6`, and `ctx.remote_port`; `bind*` and `getsockname*` expose `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`; and `sendmsg*` additionally exposes `ctx.local_ip4` / `ctx.local_ip6` over the source-address fields. `sendmsg*` still does not expose `ctx.local_port`, because the kernel surface does not provide a corresponding source-port field there. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and port fields are normalized to host byte order. The IPv6 fields are exposed as fixed arrays of four host-order `u32` words, so ordinary Nushell indexing works, for example `($ctx.user_ip6 | get 3)`. `cgroup_sock_addr` closures can return `"allow"` / `"deny"` instead of raw `1` / `0` codes. Modeled socket helpers are also available through the ordinary helper surface: `bpf_bind`, `bpf_getsockopt`, and `bpf_setsockopt` on `connect4` / `connect6`. Numeric result codes still work too.

`sk_lookup` currently attaches to a network-namespace path such as `/proc/self/ns/net`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.family`, `ctx.protocol`, `ctx.cookie`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, `ctx.ingress_ifindex`, and a typed `ctx.sk` pointer for socket projection such as `$ctx.sk.bound_dev_if`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `sk_lookup` closures can return `"pass"` / `"drop"` instead of raw `1` / `0` result codes; `"allow"` / `"deny"` aliases also work.

`sk_msg` currently attaches to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`, plus a typed `ctx.sk` pointer for socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, or `$ctx.sk.priority`. `ctx.data` / `ctx.data_end` use the same guarded packet access model as XDP and tc, so ordinary byte/scalar reads like `($ctx.data | get 0)` work. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. This initial slice is read-only and uses raw integer verdict codes; `sk_msg` closures can return `"pass"` / `"drop"` instead of raw `1` / `0`, and `"allow"` / `"deny"` aliases also work. `adjust-message --apply BYTES`, `adjust-message --cork BYTES`, `adjust-message --pull START END [--flags N]`, `adjust-message --push START LEN [--flags N]`, and `adjust-message --pop START LEN [--flags N]` are the preferred first-class message-byte surfaces here because they select the corresponding `bpf_msg_*` helper automatically from the current program type. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_msg_redirect_map` or `bpf_msg_redirect_hash` automatically from the current program type. `adjust-message --pull` can invalidate previously loaded `ctx.data` / `ctx.data_end` pointers, so reload them after the helper before reading packet bytes again. Socket-pointer helpers whose program surface includes `sk_msg` also work on the typed `ctx.sk` value after a null check, for example `if $ctx.sk != 0 { helper-call "bpf_sk_fullsock" $ctx.sk }`.

`sk_skb` currently emits `sk_skb/stream_verdict` programs attached to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.napi_id`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.ingress_ifindex`, `ctx.ifindex`, `ctx.tc_index`, `ctx.hash`, `ctx.priority`, `ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port` through the existing skb-backed packet model, so ordinary guarded packet reads like `($ctx.data | get 0)` work. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. This initial slice uses verdict-style return codes with `pass` / `drop` aliases. `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` are the preferred first-class skb relayout surfaces here because they select `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room` automatically from the current program type. Modeled skb packet-edit helpers are also available through the ordinary helper surface, including `bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_get_hash_recalc`, `bpf_csum_update`, and `bpf_set_hash_invalid`. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_sk_redirect_map` or `bpf_sk_redirect_hash` automatically from the current program type. Reload `ctx.data` and `ctx.data_end` after `adjust-packet --head`, `adjust-packet --tail`, `adjust-packet --pull`, or `adjust-packet --room` before reading packet bytes again.

`sk_skb_parser` currently emits `sk_skb/stream_parser` programs attached to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It uses the same skb-backed packet context as `sk_skb`, including `ctx.family`, `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.napi_id`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.ifindex`, `ctx.tc_index`, `ctx.hash`, `ctx.priority`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`, with the same host-order normalization rules for IPv4 addresses, remote ports, and IPv6 word arrays. Its return contract is a raw integer parser result rather than a verdict alias surface, so ordinary examples should return `0` or another integer length. `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` are the preferred first-class skb relayout surfaces here because they select `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room` automatically from the current program type. Modeled skb packet-edit helpers are also available through the ordinary helper surface, including `bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_get_hash_recalc`, `bpf_csum_update`, and `bpf_set_hash_invalid`. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_sk_redirect_map` or `bpf_sk_redirect_hash` automatically from the current program type. Reload `ctx.data` and `ctx.data_end` after `adjust-packet --head`, `adjust-packet --tail`, `adjust-packet --pull`, or `adjust-packet --room` before reading packet bytes again.

`kprobe` and `uprobe` expose `ctx.arg0`-`ctx.arg5` through `pt_regs`. `raw_tracepoint` exposes raw positional `ctx.argN` slots. `fentry`, `fexit`, `tp_btf`, `lsm`, and `struct_ops` callbacks resolve arguments from kernel BTF; those kernel-BTF-backed contexts also expose named aliases through `ctx.arg.<name>` when names are available, and `fexit` additionally exposes `ctx.retval`. Scalar and pointer trampoline values work directly. By-value trampoline args and pointer-backed trampoline args/returns can project scalar/pointer fields such as `ctx.arg0.some_field`; pointer-backed projections are lowered through null-guarded `bpf_probe_read_{kernel,user}` and can cross intermediate and repeated pointer hops such as `ctx.arg0.foo.bar` or `ctx.arg0.fdt.fd.f_inode.i_ino`. Fixed-size arrays can also be indexed with numeric path segments like `ctx.arg0.comm.0`, and pointer-backed sequences can now also be indexed with constant numeric segments such as `ctx.arg0.fdt.fd.0.f_inode.i_ino` or `let fd = $ctx.arg0.fdt.fd; $fd.0.f_inode.i_ino`. The same typed pointer traversal also works through numeric `get`, for example `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`. Stack-backed fixed arrays support the same runtime indexing, for example `let idx = ($ctx.pid mod 2); ($ctx.arg0.comm | get $idx)`. Bounded `for` loops over static integer ranges also lower to verifier-safe loops, so `for i in 0..0 { ... get $i ... }` now works, explicit negative-step descending ranges lower too, and bounded arithmetic on those indices such as `let j = (($i + 1) mod 2)` is preserved. The same range tracking now works for typed unsigned runtime fields such as `let idx = ($ctx.arg0.fdt.max_fds mod 2)`. Branch-sensitive narrowing also works for both bound and repeated direct paths, for example `let max = $ctx.arg0.fdt.max_fds; if $max > 0 { let idx = ($max - 1); ... }` or `if $ctx.arg0.fdt.max_fds > 0 { let idx = ($ctx.arg0.fdt.max_fds - 1); ... }`. Typed BTF bitfields can also be projected through the same paths, including after numeric `get`, for example `let idx = ($ctx.pid mod 2); let clamp = ($ctx.arg0.uclamp_req | get $idx); $clamp.value`. Terminal array leaves and unsupported aggregate leaves are exposed as stack-backed byte buffers, while representable terminal struct leaves keep their field layouts, including BTF bitfield members, for `count` / `ebpf counters`, and single-value `emit` can stream those struct leaves as records. Nested array/record fields inside emitted values also decode recursively when the compiler can preserve their layouts. `emit` still preserves unsupported aggregate layouts as binary payloads, and `count` supports them as byte-buffer keys. `ebpf counters` decodes those keys using any schema the compiler still has: arrays and typed structs can surface as strings, lists, or records, while opaque aggregate layouts still display as `binary`. Plain trampoline `ctx.argN` / `ctx.retval` loads also preserve their typed pointer or aggregate layouts across bindings, so `let files = $ctx.arg0; $files.fdt.fd.f_inode.i_ino`, `ctx.arg0.fdt.fd.0.f_inode.i_ino`, `let fd = $ctx.arg0.fdt.fd; $fd.0.f_inode.i_ino`, `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`, and `let inode = $ctx.arg0.f_inode; $inode.i_sb.s_flags` continue to type-check and lower as expected. Named parameter access works through the same typed lowering path, for example `ctx.arg.prev_cpu`, `ctx.arg.p.pid`, `ctx.arg.file.f_flags`, or `ctx.arg.file.f_inode.i_ino`. 16-byte byte-array/string keys such as `ctx.arg0.comm` continue to display as strings. Aggregate `fexit` returns still depend on kernel trampoline support; some kernels reject struct returns entirely.

Generic named maps are also available through `map-get`, `map-put`, `map-delete`, `map-push`, `map-peek`, and `map-pop`. `map-get`, `map-peek`, and `map-pop` return maybe-null pointers. When a prior typed `map-put` established the value layout in the same closure, projections like `let entry = ($ctx.pid | map-get seen_paths --kind hash); if $entry != 0 { $entry.dentry.d_flags }` lower through that preserved map-value schema, and whole-value uses like `{ $entry | emit }` or `{ $entry | count }` preserve the same typed aggregate layout instead of collapsing to a raw pointer scalar. That same typed `map-put` / `map-push` seeding now also accepts metadata-built record values when the record fields already have a truthful fixed layout and tracked semantics, so ordinary record construction can feed typed map flows without an intermediate local materialization step. The preserved layout also survives record construction, so `if $entry != 0 { { path: $entry } | emit }` streams `path` as a nested record instead of a raw pointer or opaque bytes. The same null-checked layout now also survives simple user-defined function boundaries, so `def project-entry [entry] { $entry }` can feed `if $entry != 0 { (project-entry $entry) | emit }` without collapsing back to an untyped scalar. Call-site typed arguments now also specialize simple user-defined functions, so callees can project typed fields directly from their parameters, for example `def inode-flags [file] { $file.f_inode.i_flags }`. Queue/stack maps now preserve their pushed value layouts the same way: a typed `map-push` establishes the layout used by later `map-peek` / `map-pop` in the same closure, and pinned peers attached with the same `--pin` group can reuse that schema too. When those looked-up aggregates are written back through `map-put`, the stored value shape stays canonical too, so map-to-map copies preserve the real aggregate layout instead of a pointer wrapper. When those maps are attached with the same `--pin` group, active pinned programs now reuse that typed schema across program boundaries too.

Leading annotated `mut` bindings at the top of an attached eBPF closure now lower as compiler-managed per-program globals backed by `.data` or `.bss`, so ordinary Nushell variable syntax can express private state without a helper: `{|ctx| mut state: int = 0; $state = ($state + 1); $state | count }`. The initializer must be a compile-time constant today, and only the leading declaration group at the top of the closure is hoisted this way. That is now the preferred small-state path when plain variable syntax is enough. For supported annotations, the declared Nushell type is now the layout source for that global, so record field order comes from the annotation rather than the record literal initializer. When the annotation itself fully fixes a truthful layout, `null` also works as a zero-initialized `.bss` initializer, for example `{|ctx| mut state: record<pid: int stats: record<hits: int ok: bool>> = null; ... }`. Partial typed record initializers follow the same rule for fixed-layout fields, so `{|ctx| mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 }; ... }` zero-fills `stats` instead of forcing a verbose full literal. That zero-init path is intentionally limited to scalar and nested scalar-record layouts whose size is fixed by the plain Nushell annotation alone; string, binary, and list globals still need an explicit exemplar or the typed named-global path so the compiler knows their real capacity. Keep those annotated `mut` declarations before function definitions and other top-level statements; a typed `mut` that appears later is not treated as a compiler-managed global.

Compiler-managed named globals are still available through `global-define`, `global-get`, and `global-set` when you need an explicit shared name or source-order-independent declaration. Leading typed `mut` bindings remain the preferred private-state path when ordinary variable syntax is enough. These named globals are compiler-managed per-program globals backed by `.data` or `.bss`. `global-define` is declarative: by default a compile-time constant input establishes the fixed layout and initial contents without doing a runtime store, so source order does not matter. `global-define --zero` takes the next step and uses the input only for layout inference, allocating a zero-initialized `.bss` global without a runtime store. If you use `global-define --type`, no exemplar is needed for the layout: with no pipeline input it declares a zero-initialized global directly, and with a compile-time constant input it combines the explicit fixed layout with explicit initial contents. Currently `i8` / `i16` / `i32` / `int` (alias `i64`), `u8` / `u16` / `u32` / `u64`, `bool`, and `bytes:N` are supported as direct typed declarations, and that now also extends to `string:N`, `list:int:N` (alias `list:i64:N`), and fixed arrays such as `array{u32:4}` or `array{record{pid:int,cpu:u32}:2}`, plus nested `record{field:type,...}` declarations whose fields can themselves be scalars, fixed `bytes:N` / `binary:N`, `string:N`, `list:int:N`, `array{type:N}`, or further `record{...}` layouts. Typed initializers are zero-padded within those declared capacities, and typed record initializers may omit fields that should start zeroed, so forms like `"bash" | global-define --type string:16 seen_comm`, `[11 22] | global-define --type 'array{u32:4}' seen_ports`, `[{pid: 7 cpu: 2} {pid: 9 cpu: 3}] | global-define --type 'array{record{pid:int,cpu:u32}:2}' seen_entries`, `{ entries: [{pid: 7 cpu: 2} {pid: 9 cpu: 3}] } | global-define --type 'record{entries:array{record{pid:int,cpu:u32}:2}}' seen_state`, `{ pid: 7, samples: [11 22] } | global-define --type 'record{pid:int,samples:list:int:4}' seen_state`, and `{ pid: 7 } | global-define --type 'record{pid:int,samples:list:int:4}' seen_state` are valid. `global-get` preserves those typed string/list/array field semantics too, so projections like `$state.msg`, `($state.vals | get 1)`, `($ports | get 0)`, `($entries | get 1).cpu`, or `($state.entries | get 1).cpu` behave the same way as the ordinary typed mutable global path. If you skip `global-define`, the first `global-set` for a given name still establishes the fixed layout used by later `global-get` and `global-set` calls in the same closure; when that first write is a compile-time constant the global is initialized from it, otherwise it starts zeroed. That same first-write inference now also works for metadata-built record values, including nested record builders, when every field already has a truthful fixed layout and tracked semantics, so ordinary record construction can seed named globals without an intermediate local materialization step. They are best suited for small per-program state without the overhead of an explicit map. Like the current mutable-capture path, they only support values with a truthful fixed layout.

Generic map `--kind` now supports `hash`, `array`, `queue`, `stack`, `lpm-trie`, `lru-hash`, `per-cpu-hash`, `per-cpu-array`, and `lru-per-cpu-hash`. `queue` and `stack` use `map-push`, `map-peek`, and `map-pop` instead of `map-put` / `map-get`. `lpm-trie` uses the kernel's raw trie-key layout, so the key bytes must already begin with a `u32` prefix length followed by the trie payload.

`redirect-map` is the first-class XDP surface for `bpf_redirect_map`. It takes a literal map name plus a key, requires `--kind devmap`, `--kind devmap-hash`, `--kind cpumap`, or `--kind xskmap`, and returns the helper result directly so it can be the closure's final XDP action. `--flags` stays available for the helper's fallback return-code bits when the map lookup misses.

`adjust-packet` is the first-class packet-relayout surface. On XDP it takes a delta from pipeline input or a positional argument, requires exactly one of `--head`, `--meta`, or `--tail`, and lowers to the corresponding `bpf_xdp_adjust_*` helper while materializing the ambient context pointer automatically. On `tc`, `sk_skb`, and `sk_skb_parser`, `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` do the same for the skb relayout helpers.

`adjust-message` is the first-class `sk_msg` byte-window and reshaping surface. `adjust-message --apply BYTES` and `adjust-message --cork BYTES` lower to `bpf_msg_apply_bytes` and `bpf_msg_cork_bytes`. `adjust-message --pull START END [--flags N]`, `adjust-message --push START LEN [--flags N]`, and `adjust-message --pop START LEN [--flags N]` lower to `bpf_msg_pull_data`, `bpf_msg_push_data`, and `bpf_msg_pop_data`. The ambient message context pointer is materialized automatically and the helper result is returned directly.

`redirect` is the first-class packet redirect surface for XDP and tc. It takes an ifindex from pipeline input or a positional argument and returns the helper result directly. Plain `redirect IFINDEX` lowers to `bpf_redirect`. `redirect --peer IFINDEX` lowers to `bpf_redirect_peer` on `tc:...:ingress`, and `redirect --neigh IFINDEX` lowers to the default-neighbor `bpf_redirect_neigh(IFINDEX, 0, 0, FLAGS)` form on tc. `--flags` stays available for the helper's flags argument.

`redirect-socket` is the first-class socket redirect surface for `sk_msg`, `sk_skb`, and `sk_skb_parser`. It takes a literal map name plus a key, requires `--kind sockmap` or `--kind sockhash`, selects the appropriate socket redirect helper from the current program type, and returns that helper result directly. `--flags` stays available for the helper's final argument.

Read-only closure captures now lower as real constants for supported types (`int`, `bool`, `string`, `binary`, `nothing`, constant records, numeric constant lists, and homogeneous fixed arrays of scalar/binary/record constants`) instead of only working when inlined manually. That means existing Nushell structure can keep driving compile-time positions such as generic map names, for example `let map_name = "seen_paths"; $ctx.arg0.f_path | map-put $map_name $ctx.pid --kind hash`. Reassigned captured numeric scalars, strings, fixed binary values, numeric constant lists, homogeneous fixed arrays, and representable constant records now take the next step and lower as compiler-managed mutable globals backed by `.data` or `.bss`, so ordinary Nushell variable flow can express per-program state without dropping down to explicit maps for the smallest cases. Leading typed `mut` list initializers can also use homogeneous scalar/binary/record constants as fixed-array globals when the initializer provides the concrete length and layout, for example `mut entries: list<record<pid: int cpu: int>> = [{pid: 7, cpu: 2} {pid: 9, cpu: 3}]`; the same fixed-array layout is available for typed list fields nested inside typed record `mut` globals. That mutable path is still intentionally honest: it works for values with a real byte layout and tracked runtime metadata, and metadata-only record builders are accepted only when the compiler can derive a truthful fixed record layout, including nested record-builder fields, and materialize them on demand before the global store.

## Language Surface Policy

- Prefer ordinary Nushell syntax plus the small first-class eBPF command set (`emit`, `count`, `histogram`, `start-timer`, `stop-timer`, `read-str`, `read-kernel-str`, `adjust-packet`, `adjust-message`, `redirect`, `redirect-map`, and `redirect-socket`) whenever the operation has an honest language form.
- Keep that permanent first-class surface intentionally small. Those commands should exist because they model real eBPF operations that do not already have a clear Nushell shape, not because every helper needs a bespoke wrapper.
- Prefer leading typed `mut` bindings for private compiler-managed globals. Use `global-define`, `global-get`, and `global-set` when you truly need an explicit shared name or a source-order-independent declaration.
- Treat `map-*` and `global-*` as convenience surface around concrete eBPF capabilities, not as a goal to invent a second parallel language when plain Nushell syntax would be clearer. They are justified when they name a real map/global resource directly; they are not a template for growing new wrappers by default.
- Treat `helper-call` and `kfunc-call` as escape hatches for kernel ABI surface we have not yet lifted into a smaller, more idiomatic language primitive.
- Compiler-internal helper and kfunc modeling is permanent even if escape-hatch commands shrink later. The compiler still has to know signatures, legal program families, pointer/ref semantics, and verifier-facing rules.

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
| `adjust-packet` | Packet relayout (`xdp`: `--head` / `--meta` / `--tail`; `tc` / `sk_skb` / `sk_skb_parser`: `--head` / `--tail` / `--pull` / `--room`) |
| `adjust-message` | `sk_msg` byte-window and reshaping control (`--apply`, `--cork`, `--pull`, `--push`, or `--pop`) |
| `redirect` | XDP/tc redirect by ifindex (`--peer` and `--neigh` select the tc-only helper variants; optional `--flags`) |
| `redirect-map` | XDP redirect through a named devmap/devmap-hash/cpumap/xskmap (`--kind` required; optional `--flags`) |
| `redirect-socket` | `sk_msg`/`sk_skb`/`sk_skb_parser` redirect through a named sockmap/sockhash (`--kind` required; optional `--flags`) |
| `helper-call` | Escape hatch: call a modeled BPF helper by literal name, such as `bpf_get_current_pid_tgid` |
| `kfunc-call` | Escape hatch: call a typed kernel kfunc by literal name, resolved from kernel BTF when possible |
| `global-define` | Declare a named compiler-managed program global when a leading typed `mut` binding is not enough; `--zero` uses a runtime exemplar, and `--type` declares an explicit scalar/`bytes:N`/`string:N`/`list:int:N` (alias `list:i64:N`)/`array{type:N}`/nested `record{field:type,...}` layout either zero-initialized or from a compile-time constant initializer |
| `global-get` | Load a named compiler-managed program global declared with `global-define` or inferred from `global-set` |
| `global-set` | Store the pipeline input into a named compiler-managed program global |
| `map-get` | Look up a value pointer in a named generic map |
| `map-put` | Insert or update a value in a named generic map |
| `map-delete` | Delete a key from a named generic map |
| `map-push` | Push the pipeline input into a named queue or stack map |
| `map-peek` | Peek a maybe-null value pointer from a named queue or stack map |
| `map-pop` | Pop a maybe-null value pointer from a named queue or stack map |

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
