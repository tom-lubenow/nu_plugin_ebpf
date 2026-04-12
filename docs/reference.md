# Language And Context Reference

Detailed reference for the current compiler surface. See the [README](../README.md) for the front-page guide and the [example gallery](examples.md) for runnable snippets.

## Context Fields

The closure receives a context parameter with these fields:

| Field | Description | Probe Types |
|-------|-------------|-------------|
| `pid` | Thread ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `tgid` | Process ID (thread group) | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `uid` | User ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `gid` | Group ID | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `comm` | Process name (16 bytes) | kprobe, kretprobe, fentry, fexit, tracepoint, raw_tracepoint, uprobe, uretprobe |
| `cgroup_id` | Current task cgroup ID | all current program types |
| `cpu` | CPU ID | All |
| `ktime` | Kernel timestamp (ns) | All |
| `packet_len` | Packet length (`data_end - data` on XDP, `skb->len` on skb-backed packet programs, `size` on sk_msg, `skb_len` on packet-aware sock_ops callbacks) | xdp, socket_filter, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `pkt_type` | skb pkt_type | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `queue_mapping` | skb queue_mapping | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `eth_protocol` | skb protocol / ethertype in host byte order | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `vlan_present` | Whether skb VLAN metadata is present | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `vlan_tci` | skb VLAN TCI | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `vlan_proto` | skb VLAN ethertype in host byte order | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `cb` | skb control-block words as five host-order `u32` values | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `tc_classid` | skb tc_classid | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `napi_id` | skb napi_id | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `wire_len` | skb wire_len | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `gso_segs` | skb GSO segment count | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `gso_size` | skb GSO segment size | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `hwtstamp` | skb hardware timestamp | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `data` | Packet data pointer | xdp, socket_filter, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `data_end` | Packet end pointer | xdp, socket_filter, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `ingress_ifindex` | Ingress interface index | xdp, socket_filter, tc, cgroup_skb, sk_lookup, sk_skb, sk_skb_parser |
| `access_type` | Encoded cgroup device access type | cgroup_device |
| `major` | Requested device major number | cgroup_device |
| `minor` | Requested device minor number | cgroup_device |
| `ifindex` | Interface index (`xdp_md.ingress_ifindex` on XDP, `__sk_buff.ifindex` on skb-backed packet programs) | xdp, socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `tc_index` | skb tc_index | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `hash` | skb hash | socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `socket_cookie` | Stable kernel socket cookie, or `0` when an skb has no known socket | socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_skb, sk_skb_parser, sock_ops |
| `socket_uid` | Owner UID of the socket associated with the current skb | socket_filter, tc, cgroup_skb, sk_skb |
| `netns_cookie` | Stable kernel network-namespace cookie | socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, sock_ops |
| `rx_queue_index` | XDP receive queue index | xdp |
| `egress_ifindex` | XDP egress interface index | xdp |
| `user_family` | Userspace-requested socket family | cgroup_sock_addr |
| `user_ip4` | IPv4 destination/source address in host byte order | cgroup_sock_addr (*4 hooks) |
| `user_ip6` | IPv6 address as four host-order `u32` words | cgroup_sock_addr (*6 hooks) |
| `user_port` | Requested port in host byte order | cgroup_sock_addr |
| `family` | Kernel socket family | cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `sock_type` | Socket type | cgroup_sock, cgroup_sock_addr |
| `protocol` | Socket protocol | cgroup_sock, cgroup_sock_addr, sk_lookup |
| `bound_dev_if` | Bound device ifindex | cgroup_sock |
| `mark` | Socket or skb mark | cgroup_sock, socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
| `priority` | Socket or skb priority | cgroup_sock, socket_filter, tc, cgroup_skb, sk_skb, sk_skb_parser |
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
| `msg_src_ip4` | IPv4 source address in host byte order | cgroup_sock_addr (sendmsg4, recvmsg4) |
| `msg_src_ip6` | IPv6 source address as four host-order `u32` words | cgroup_sock_addr (sendmsg6, recvmsg6) |
| `remote_ip4` | Remote IPv4 address in host byte order | sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `remote_ip6` | Remote IPv6 address as four host-order `u32` words | sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `remote_port` | Remote port in host byte order | sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_ip4` | Local IPv4 address in host byte order | sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_ip6` | Local IPv6 address as four host-order `u32` words | sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_port` | Local port in host byte order | sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `sk` | Typed `bpf_sock *` pointer for socket projection such as `$ctx.sk.family` or `$ctx.sk.bound_dev_if`; currently exposes `bound_dev_if`, `family`, `type`, `protocol`, `mark`, `priority`, `src_port`, `dst_port` (raw network byte order), `state`, and `rx_queue_mapping` | cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_lookup, sk_msg, sock_ops |
| `cookie` | Socket lookup cookie | sk_lookup |
| `level` | Socket-option level | cgroup_sockopt |
| `optname` | Socket-option name | cgroup_sockopt |
| `optlen` | Socket-option length | cgroup_sockopt |
| `optval` | Kernel pointer to the sockopt buffer | cgroup_sockopt |
| `optval_end` | Kernel pointer to the end of the sockopt buffer | cgroup_sockopt |
| `sockopt_retval` | Getsockopt return value on `get` hooks | cgroup_sockopt |
| `arg0`-`argN` | Function arguments; kernel-BTF-backed contexts also expose named `ctx.arg.<name>` aliases when kernel BTF includes names | kprobe, uprobe, fentry, fexit, tp_btf, lsm, struct_ops, raw_tracepoint |
| `retval` | Return value | kretprobe, uretprobe, fexit |

Tracepoint fields are read from `/sys/kernel/tracing/events/<category>/<name>/format`.

## Program-Family Notes

`xdp`, `socket_filter`, `tc`, and `cgroup_skb` all expose `ctx.cpu`, `ctx.ktime`, `ctx.packet_len`, `ctx.ingress_ifindex`, `ctx.ifindex`, and raw packet pointers `ctx.data` and `ctx.data_end`. Scalar packet byte reads work through normal Nushell indexing such as `($ctx.data | get 0)`, and fixed-width big-endian scalars can be read directly through cell paths such as `$ctx.data.u16be.6` or `$ctx.data.u32be.0`. These lower to data_end-guarded packet loads. Fixed header views `eth`, `ipv4`, `udp`, and `tcp` are also available, for example `$ctx.data.eth.ethertype` or `$ctx.data.eth.dst.0`. Those header views also support `payload` stepping: `$ctx.data.eth.payload` skips Ethernet and a single VLAN tag when present, `$ctx.data.eth.payload.ipv4.payload` skips a runtime-sized IPv4 header using the IHL nibble, and `$ctx.data.eth.payload.ipv4.payload.tcp.payload` skips a runtime-sized TCP header using the data offset. `xdp` additionally exposes `ctx.ifindex`, `ctx.rx_queue_index`, and `ctx.egress_ifindex`. The skb-backed packet contexts (`socket_filter`, `tc`, `cgroup_skb`, `sk_skb`, and `sk_skb_parser`) also expose `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.tc_classid`, `ctx.napi_id`, `ctx.wire_len`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.hwtstamp`, `ctx.tc_index`, `ctx.hash`, `ctx.mark`, and `ctx.priority`. `ctx.eth_protocol` and `ctx.vlan_proto` are normalized to host byte order, and `ctx.cb` follows the same fixed-array model as `ctx.args`. The initial `socket_filter` surface uses targets like `socket_filter:udp4:127.0.0.1:31337`, `socket_filter:udp6:[::1]:31337`, `socket_filter:tcp4:127.0.0.1:31337`, and `socket_filter:tcp6:[::1]:31337`, which create and keep open a bound socket while attached. `socket_filter` return values are snapshot lengths: return `0` to drop the packet or a positive value to keep it, and aliases like `"pass"` / `"keep"` expand to `ctx.packet_len`. Variable header lengths, VLAN options parsing, deeper TCP option parsing, stacked VLAN tags, and named packet-program action helpers are still not modeled, but compile-time action aliases are available in return position. XDP closures can return strings like `"pass"` / `"drop"`, and TC closures can return strings like `"ok"` / `"shot"`. Raw numeric return codes still work, and `helper-call "bpf_redirect" IFINDEX FLAGS` is now type-checked on XDP/TC paths; XDP requires `FLAGS = 0`. On `tc:...:ingress`, `helper-call "bpf_redirect_peer" IFINDEX FLAGS` is also modeled and requires `FLAGS = 0`. TC programs also support the default-neighbor form of `helper-call "bpf_redirect_neigh" IFINDEX 0 0 0`.

`perf_event` currently supports software `cpu-clock`, `task-clock`, `context-switches`, `cpu-migrations`, `page-faults`, `minor-faults`, and `major-faults`, plus hardware `cpu-cycles`, `instructions`, `cache-references`, `cache-misses`, `branch-instructions`, `branch-misses`, `bus-cycles`, `stalled-cycles-frontend`, `stalled-cycles-backend`, and `ref-cpu-cycles` through specs like `perf_event:software:cpu-clock` or `perf_event:hardware:cpu-cycles`. Optional selectors `cpu=N`, `pid=N`, `period=N`, and `freq=N` are supported; omitting the sample policy defaults to `period=1000000`, and omitting `cpu=` attaches on all online CPUs. `pid=N` scopes the event to a single process, and it can be combined with `cpu=N` for one-process/one-cpu sampling. The initial surface uses the ordinary helper-backed fields like `ctx.pid`, `ctx.comm`, `ctx.cpu`, and `ctx.ktime`.

`cgroup_sock` currently supports `sock_create`, `sock_release`, `post_bind4`, and `post_bind6`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.family`, `ctx.sock_type`, `ctx.protocol`, `ctx.bound_dev_if`, `ctx.mark`, `ctx.priority`, `ctx.socket_cookie`, and `ctx.netns_cookie`, and closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. On `cgroup_sock`, the socket-address projection fields such as `$ctx.sk.src_port` and `$ctx.sk.dst_port` are only available on `post_bind4` / `post_bind6`.

`cgroup_device` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.access_type`, `ctx.major`, and `ctx.minor`, and closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes. `ctx.access_type` is the raw kernel encoding `(BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*`.

`sock_ops` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes the sock_ops callback opcode and argument words (`ctx.op`, `ctx.args`), the socket tuple and metadata fields (`ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, `ctx.socket_cookie`, `ctx.netns_cookie`), the TCP/congestion and progress counters (`ctx.is_fullsock`, `ctx.snd_cwnd`, `ctx.srtt_us`, `ctx.cb_flags`, `ctx.state`, `ctx.rtt_min`, `ctx.snd_ssthresh`, `ctx.rcv_nxt`, `ctx.snd_nxt`, `ctx.snd_una`, `ctx.mss_cache`, `ctx.ecn_flags`, `ctx.rate_delivered`, `ctx.rate_interval_us`, `ctx.packets_out`, `ctx.retrans_out`, `ctx.total_retrans`, `ctx.segs_in`, `ctx.data_segs_in`, `ctx.segs_out`, `ctx.data_segs_out`, `ctx.lost_out`, `ctx.sacked_out`, `ctx.sk_txhash`, `ctx.bytes_received`, and `ctx.bytes_acked`), plus packet-metadata fields `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.skb_len`, `ctx.skb_tcp_flags`, and `ctx.skb_hwtstamp` when the callback context has packet data available. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and remote port fields are normalized to host byte order. The IPv6 fields are exposed as fixed arrays of four host-order `u32` words, so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `ctx.reply` and `ctx.replylong.<0-3>` are writable raw `u32` words and can be assigned with ordinary Nushell cell-path updates after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.reply = 1` or `mut ctx = $ctx; $ctx.replylong.0 = 7`. Packet-aware callbacks use the same guarded packet-access model as XDP and tc, so forms like `($ctx.data | get 0)` are valid there. Modeled socket-option helpers are also available through the ordinary helper surface, including `bpf_getsockopt` and `bpf_setsockopt`. sock_ops uses raw integer return codes; observation-only examples should return `1`.

`cgroup_sock_addr` currently exposes `ctx.cpu`, `ctx.ktime`, `ctx.socket_cookie`, `ctx.netns_cookie`, `ctx.user_family`, `ctx.user_ip4`, `ctx.user_ip6`, `ctx.user_port`, `ctx.family`, `ctx.sock_type`, `ctx.protocol`, `ctx.msg_src_ip4`, and `ctx.msg_src_ip6`. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and port fields are normalized to host byte order. The IPv6 fields are exposed as fixed arrays of four host-order `u32` words, so ordinary Nushell indexing works, for example `($ctx.user_ip6 | get 3)`. `cgroup_sock_addr` closures can return `"allow"` / `"deny"` instead of raw `1` / `0` codes. Modeled socket helpers are also available through the ordinary helper surface: `bpf_bind` on `connect4` / `connect6`, and `bpf_getsockopt` / `bpf_setsockopt` on the current `bind*`, `connect*`, `getpeername*`, `getsockname*`, `sendmsg*`, and `recvmsg*` hooks. Numeric result codes still work too.

`sk_lookup` currently attaches to a network-namespace path such as `/proc/self/ns/net`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.family`, `ctx.protocol`, `ctx.cookie`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, `ctx.ingress_ifindex`, and a typed `ctx.sk` pointer for socket projection such as `$ctx.sk.bound_dev_if`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `sk_lookup` closures can return `"pass"` / `"drop"` instead of raw `1` / `0` result codes; `"allow"` / `"deny"` aliases also work.

`sk_msg` currently attaches to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`, plus a typed `ctx.sk` pointer for socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.priority`. `ctx.data` / `ctx.data_end` use the same guarded packet access model as XDP and tc, so ordinary byte/scalar reads like `($ctx.data | get 0)` work. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. This initial slice is read-only and uses raw integer verdict codes; `sk_msg` closures can return `"pass"` / `"drop"` instead of raw `1` / `0`, and `"allow"` / `"deny"` aliases also work. Modeled socket-message helpers are available through the ordinary helper surface, for example `helper-call "bpf_msg_apply_bytes" $ctx 8` or `helper-call "bpf_msg_cork_bytes" $ctx 8`, plus range/data reshaping forms like `helper-call "bpf_msg_pull_data" $ctx 0 8 0` and `helper-call "bpf_msg_push_data" $ctx 0 8 0` or `helper-call "bpf_msg_pop_data" $ctx 0 8 0`. Socket-pointer helpers also work on the typed `ctx.sk` value after a null check, for example `if $ctx.sk != 0 { helper-call "bpf_sk_cgroup_id" $ctx.sk }`.

`sk_skb` currently emits `sk_skb/stream_verdict` programs attached to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.packet_len`, `ctx.data`, `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.tc_classid`, `ctx.napi_id`, `ctx.wire_len`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.hwtstamp`, `ctx.data_end`, `ctx.ingress_ifindex`, `ctx.ifindex`, `ctx.tc_index`, `ctx.hash`, `ctx.mark`, `ctx.priority`, `ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port` through the existing skb-backed packet model, so ordinary guarded packet reads like `($ctx.data | get 0)` work. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. This initial slice uses verdict-style return codes with `pass` / `drop` aliases.

`sk_skb_parser` currently emits `sk_skb/stream_parser` programs attached to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It uses the same skb-backed packet context as `sk_skb`, including `ctx.family`, `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.tc_classid`, `ctx.napi_id`, `ctx.wire_len`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.hwtstamp`, `ctx.ifindex`, `ctx.tc_index`, `ctx.hash`, `ctx.mark`, `ctx.priority`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`, with the same host-order normalization rules for IPv4 addresses, remote ports, and IPv6 word arrays. Its return contract is a raw integer parser result rather than a verdict alias surface, so ordinary examples should return `0` or another integer length.

`kprobe` and `uprobe` expose `ctx.arg0`-`ctx.arg5` through `pt_regs`. `raw_tracepoint` exposes raw positional `ctx.argN` slots. `fentry`, `fexit`, `tp_btf`, `lsm`, and `struct_ops` callbacks resolve arguments from kernel BTF; those kernel-BTF-backed contexts also expose named aliases through `ctx.arg.<name>` when names are available, and `fexit` additionally exposes `ctx.retval`. Scalar and pointer trampoline values work directly. By-value trampoline args and pointer-backed trampoline args/returns can project scalar/pointer fields such as `ctx.arg0.some_field`; pointer-backed projections are lowered through null-guarded `bpf_probe_read_{kernel,user}` and can cross intermediate and repeated pointer hops such as `ctx.arg0.foo.bar` or `ctx.arg0.fdt.fd.f_inode.i_ino`. Fixed-size arrays can also be indexed with numeric path segments like `ctx.arg0.comm.0`, and pointer-backed sequences can now also be indexed with constant numeric segments such as `ctx.arg0.fdt.fd.0.f_inode.i_ino` or `let fd = $ctx.arg0.fdt.fd; $fd.0.f_inode.i_ino`. The same typed pointer traversal also works through numeric `get`, for example `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`. Stack-backed fixed arrays support the same runtime indexing, for example `let idx = ($ctx.pid mod 2); ($ctx.arg0.comm | get $idx)`. Bounded ascending `for` loops over static integer ranges also lower to verifier-safe loops, so `for i in 0..0 { ... get $i ... }` now works, and bounded arithmetic on those indices such as `let j = (($i + 1) mod 2)` is preserved too. The same range tracking now works for typed unsigned runtime fields such as `let idx = ($ctx.arg0.fdt.max_fds mod 2)`; descending ranges are still rejected. Branch-sensitive narrowing also works for both bound and repeated direct paths, for example `let max = $ctx.arg0.fdt.max_fds; if $max > 0 { let idx = ($max - 1); ... }` or `if $ctx.arg0.fdt.max_fds > 0 { let idx = ($ctx.arg0.fdt.max_fds - 1); ... }`. Typed BTF bitfields can also be projected through the same paths, including after numeric `get`, for example `let idx = ($ctx.pid mod 2); let clamp = ($ctx.arg0.uclamp_req | get $idx); $clamp.value`. Terminal array leaves and unsupported aggregate leaves are exposed as stack-backed byte buffers, while representable terminal struct leaves keep their field layouts, including BTF bitfield members, for `count` / `ebpf counters`, and single-value `emit` can stream those struct leaves as records. Nested array/record fields inside emitted values also decode recursively when the compiler can preserve their layouts. `emit` still preserves unsupported aggregate layouts as binary payloads, and `count` supports them as byte-buffer keys. `ebpf counters` decodes those keys using any schema the compiler still has: arrays and typed structs can surface as strings, lists, or records, while opaque aggregate layouts still display as `binary`. Plain trampoline `ctx.argN` / `ctx.retval` loads also preserve their typed pointer or aggregate layouts across bindings, so `let files = $ctx.arg0; $files.fdt.fd.f_inode.i_ino`, `ctx.arg0.fdt.fd.0.f_inode.i_ino`, `let fd = $ctx.arg0.fdt.fd; $fd.0.f_inode.i_ino`, `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`, and `let inode = $ctx.arg0.f_inode; $inode.i_sb.s_flags` continue to type-check and lower as expected. Named parameter access works through the same typed lowering path, for example `ctx.arg.prev_cpu`, `ctx.arg.p.pid`, `ctx.arg.file.f_flags`, or `ctx.arg.file.f_inode.i_ino`. 16-byte byte-array/string keys such as `ctx.arg0.comm` continue to display as strings. Aggregate `fexit` returns still depend on kernel trampoline support; some kernels reject struct returns entirely.

Generic named maps are also available through `map-get`, `map-put`, `map-delete`, and `map-push`. `map-get` returns a maybe-null map-value pointer. When a prior typed `map-put` established the value layout in the same closure, projections like `let entry = ($ctx.pid | map-get seen_paths --kind hash); if $entry != 0 { $entry.dentry.d_flags }` lower through that preserved map-value schema, and whole-value uses like `{ $entry | emit }` or `{ $entry | count }` preserve the same typed aggregate layout instead of collapsing to a raw pointer scalar. That preserved layout also survives record construction, so `if $entry != 0 { { path: $entry } | emit }` streams `path` as a nested record instead of a raw pointer or opaque bytes. The same null-checked layout now also survives simple user-defined function boundaries, so `def project-entry [entry] { $entry }` can feed `if $entry != 0 { (project-entry $entry) | emit }` without collapsing back to an untyped scalar. Call-site typed arguments now also specialize simple user-defined functions, so callees can project typed fields directly from their parameters, for example `def inode-flags [file] { $file.f_inode.i_flags }`. When those looked-up aggregates are written back through `map-put`, the stored value shape stays canonical too, so map-to-map copies preserve the real aggregate layout instead of a pointer wrapper. When those maps are attached with the same `--pin` group, active pinned programs now reuse that typed schema across program boundaries too.

Leading annotated `mut` bindings at the top of an attached eBPF closure now lower as compiler-managed per-program globals backed by `.data` or `.bss`, so ordinary Nushell variable syntax can express private state without a helper: `{|ctx| mut state: int = 0; $state = ($state + 1); $state | count }`. The initializer must be a compile-time constant today, and only the leading declaration group at the top of the closure is hoisted this way. That is now the preferred small-state path when plain variable syntax is enough. For supported annotations, the declared Nushell type is now the layout source for that global, so record field order comes from the annotation rather than the record literal initializer. Keep those annotated `mut` declarations before function definitions and other top-level statements; a typed `mut` that appears later is not treated as a compiler-managed global.

Compiler-managed named globals are still available through `global-define`, `global-get`, and `global-set` when you need an explicit shared name or source-order-independent declaration. Leading typed `mut` bindings remain the preferred private-state path when ordinary variable syntax is enough. These named globals are compiler-managed per-program globals backed by `.data` or `.bss`. `global-define` is declarative: by default a compile-time constant input establishes the fixed layout and initial contents without doing a runtime store, so source order does not matter. `global-define --zero` takes the next step and uses the input only for layout inference, allocating a zero-initialized `.bss` global without a runtime store. If you use `global-define --type`, no exemplar is needed at all: currently `i8` / `i16` / `i32` / `i64`, `u8` / `u16` / `u32` / `u64`, `bool`, and `bytes:N` are supported as direct zero-initialized declarations, and that now also extends to `string:N` and `list:i64:N` using the same runtime layouts as ordinary mutable string/list globals, plus nested `record{field:type,...}` declarations whose fields can themselves be scalars, fixed `bytes:N` / `binary:N`, `string:N`, `list:i64:N`, or further `record{...}` layouts. `global-get` preserves those typed string/list field semantics too, so projections like `$state.msg` or `($state.vals | get 1)` behave the same way as the ordinary typed mutable global path. If you skip `global-define`, the first `global-set` for a given name still establishes the fixed layout used by later `global-get` and `global-set` calls in the same closure; when that first write is a compile-time constant the global is initialized from it, otherwise it starts zeroed. They are best suited for small per-program state without the overhead of an explicit map. Like the current mutable-capture path, they only support values with a truthful fixed layout.

Generic map `--kind` now supports `hash`, `array`, `queue`, `stack`, `lpm-trie`, `lru-hash`, `per-cpu-hash`, `per-cpu-array`, and `lru-per-cpu-hash`. `queue` and `stack` use `map-push` instead of `map-put` / `map-get`. `lpm-trie` uses the kernel's raw trie-key layout, so the key bytes must already begin with a `u32` prefix length followed by the trie payload.

Read-only closure captures now lower as real constants for supported types (`int`, `bool`, `string`, `binary`, `nothing`, constant records, and numeric constant lists`) instead of only working when inlined manually. That means existing Nushell structure can keep driving compile-time positions such as generic map names, for example `let map_name = "seen_paths"; $ctx.arg0.f_path | map-put $map_name $ctx.pid --kind hash`. Reassigned captured numeric scalars, strings, fixed binary values, numeric constant lists, and representable constant records now take the next step and lower as compiler-managed mutable globals backed by `.data` or `.bss`, so ordinary Nushell variable flow can express per-program state without dropping down to explicit maps for the smallest cases. That mutable path is still intentionally honest: it works for values with a real byte layout and tracked runtime metadata, not for metadata-only record builders that have never been materialized.

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
| `helper-call` | Call a modeled BPF helper by name, such as `bpf_get_current_pid_tgid` |
| `kfunc-call` | Call a typed kernel kfunc by name, resolved from kernel BTF when possible |
| `global-define` | Declare a named compiler-managed program global when a leading typed `mut` binding is not enough; `--zero` uses a runtime exemplar, `--type` declares a zero-initialized scalar, `bytes:N`, `string:N`, `list:i64:N`, or nested `record{field:type,...}` global directly |
| `global-get` | Load a named compiler-managed program global declared with `global-define` or inferred from `global-set` |
| `global-set` | Store the pipeline input into a named compiler-managed program global |
| `map-get` | Look up a value pointer in a named generic map |
| `map-put` | Insert or update a value in a named generic map |
| `map-delete` | Delete a key from a named generic map |
| `map-push` | Push the pipeline input into a named queue or stack map |

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
