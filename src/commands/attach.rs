//! `ebpf attach` command - attach an eBPF probe

use std::collections::{HashMap, HashSet};

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Record, Signature, Span, SyntaxShape, Type,
    Value, record,
};

use crate::EbpfPlugin;
use crate::compiler::{EbpfObject, ProbeContext, StructOpsObjectSpec, StructOpsValueField};
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};

mod compilation;
mod event_stream;
mod struct_ops;

use self::compilation::{
    compile_closure_with_context, compile_struct_ops_object, value_to_spanned_closure,
};
#[cfg(test)]
use self::compilation::{
    extract_decl_names_from_formatted_instructions, map_leading_annotated_mut_globals,
    parse_inline_user_function_signatures, strip_leading_annotated_mut_initializer_stmts,
};
#[cfg(target_os = "linux")]
use self::event_stream::EventStreamIterator;
use self::struct_ops::validate_struct_ops_attach_safety;
#[cfg(test)]
use self::struct_ops::{
    StructOpsTopLevelFieldKind, apply_struct_ops_value_field, default_struct_ops_object_name,
    validate_required_struct_ops_callbacks, validate_required_struct_ops_value_fields,
    validate_sched_ext_callback_kfunc_requirements, validate_struct_ops_top_level_field_kind,
};

#[derive(Clone)]
pub struct EbpfAttach;

impl PluginCommand for EbpfAttach {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf attach"
    }

    fn description(&self) -> &str {
        "Attach an eBPF program to a kernel hook such as a probe, tracepoint, userspace function, or packet hook."
    }

    fn extra_description(&self) -> &str {
        r#"This command compiles a Nushell closure to eBPF bytecode and attaches
it to the specified probe point. The closure runs in the kernel whenever
the probe point is hit.

Supported attach types:
  - kprobe, kretprobe
  - fentry, fexit, tp_btf
  - tracepoint, raw_tracepoint
  - uprobe, uretprobe
  - lsm
  - perf_event
  - socket_filter
  - xdp, tc
  - cgroup_skb
  - cgroup_device
  - cgroup_sock
  - sock_ops
  - sk_msg
  - sk_skb
  - sk_skb_parser
  - cgroup_sysctl
  - cgroup_sockopt
  - cgroup_sock_addr
  - sk_lookup
  - lirc_mode2
  - struct_ops

Body forms:
  - Ordinary program types use a closure body: {|ctx| ... }
  - struct_ops uses a record body whose callback fields are closures and whose
    simple top-level value fields are compile-time constants:
      { select_cpu: {|ctx| 0 }, name: "demo" }
    Top-level value fields currently accept int, bool, string, binary, and
    constant int-list values for fixed integer arrays.
    Nested record values are also supported for by-value substruct members.
    Nested list values are also supported for by-value array members, including
    arrays of records.
    Pointer-hop field initialization is still rejected.

Context parameter syntax (recommended):
  The closure can take a context parameter to access program context information:

  Universal tracing fields (all tracing attach types):
    {|ctx| $ctx.pid }     - Get process ID (thread ID)
    {|ctx| $ctx.tgid }    - Get thread group ID (process ID)
    {|ctx| $ctx.uid }     - Get user ID
    {|ctx| $ctx.gid }     - Get group ID
    {|ctx| $ctx.comm }    - Get process command name (first 16 bytes)
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.cgroup_id } - Get the current task cgroup ID

  Packet-context fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.cgroup_id } - Get the current task cgroup ID
    {|ctx| $ctx.packet_len } - Get packet length from xdp_md or __sk_buff
    {|ctx| $ctx.pkt_type } - Get the skb pkt_type on skb-backed packet programs
    {|ctx| $ctx.queue_mapping } - Get the skb queue_mapping on skb-backed packet programs
    {|ctx| $ctx.eth_protocol } - Get the skb protocol / ethertype in host byte order on skb-backed packet programs
    {|ctx| $ctx.vlan_present } - Get whether skb VLAN metadata is present on skb-backed packet programs
    {|ctx| $ctx.vlan_tci } - Get the skb VLAN TCI on skb-backed packet programs
    {|ctx| $ctx.vlan_proto } - Get the skb VLAN ethertype in host byte order on skb-backed packet programs
    {|ctx| $ctx.cb } - Get the skb cb words as a fixed array on skb-backed packet programs
    {|ctx| $ctx.tc_classid } - Get the skb tc_classid on skb-backed packet programs
    {|ctx| $ctx.napi_id } - Get the skb napi_id on skb-backed packet programs
    {|ctx| $ctx.wire_len } - Get the skb wire_len on skb-backed packet programs
    {|ctx| $ctx.gso_segs } - Get the skb gso_segs on skb-backed packet programs
    {|ctx| $ctx.gso_size } - Get the skb gso_size on skb-backed packet programs
    {|ctx| $ctx.hwtstamp } - Get the skb hardware timestamp on skb-backed packet programs
    {|ctx| $ctx.data }    - Get packet data pointer
    {|ctx| $ctx.data_end } - Get packet end pointer
    {|ctx| $ctx.ingress_ifindex } - Get ingress interface index
    {|ctx| $ctx.ifindex } - Get the XDP ingress ifindex or skb ifindex, depending on program type
    {|ctx| $ctx.tc_index } - Get the skb tc_index on skb-backed packet programs
    {|ctx| $ctx.hash }    - Get the skb hash on skb-backed packet programs
    {|ctx| $ctx.socket_cookie } - Get the stable socket cookie on supported socket-backed contexts
    {|ctx| $ctx.socket_uid } - Get the socket owner UID on socket_filter, tc, cgroup_skb, and sk_skb
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie on supported socket-backed contexts
    {|ctx| $ctx.mark }    - Get the skb mark on skb-backed packet programs
    {|ctx| $ctx.priority } - Get the skb priority on skb-backed packet programs
    {|ctx| ($ctx.data | get 0) } - Read the first packet byte with an auto-generated data_end guard
    {|ctx| $ctx.data.u16be.6 } - Read a big-endian 16-bit packet scalar (here: bytes 12..13)
    {|ctx| $ctx.data.eth.ethertype } - Read the Ethernet ethertype through a typed packet header view
    {|ctx| $ctx.data.eth.payload.ipv4.protocol } - Step past Ethernet and up to two stacked VLAN tags, then parse IPv4
    {|ctx| $ctx.data.eth.payload.ipv6.next_header } - Step past Ethernet and up to two stacked VLAN tags, then parse IPv6
    {|ctx| $ctx.data.eth.payload.ipv4.payload.icmp.type } - Step through IPv4 and read the ICMP type byte
    {|ctx| $ctx.data.eth.payload.ipv6.payload.icmpv6.code } - Step through IPv6 and read the ICMPv6 code byte
    {|ctx| $ctx.data.eth.payload.ipv4.payload.tcp.payload.0 } - Step through variable IPv4/TCP headers and read the first TCP payload byte
    XDP-only extras:
    {|ctx| $ctx.data_meta } - Get the XDP packet metadata pointer
    {|ctx| ($ctx.data_meta | get 0) } - Read the first metadata byte with an auto-generated `ctx.data` guard
    {|ctx| $ctx.rx_queue_index } - Get RX queue index
    {|ctx| $ctx.egress_ifindex } - Get egress interface index
    Note: XDP closures can return action aliases like `pass`, `drop`,
    `tx`, and `redirect`, and TC closures can return aliases like `ok`,
    `shot`, `pipe`, and `redirect`. cgroup_skb closures can return
    `allow` or `deny`. socket_filter closures can return `drop` / `deny`
    for `0`, or `pass` / `keep` / `allow` to snapshot the full packet by
    returning `ctx.packet_len`. `helper-call "bpf_redirect" IFINDEX FLAGS`
    is also type-checked on XDP/TC paths; XDP requires `FLAGS = 0`.
    XDP also models `helper-call "bpf_xdp_adjust_head" $ctx DELTA`,
    `helper-call "bpf_xdp_adjust_meta" $ctx DELTA`, and
    `helper-call "bpf_xdp_adjust_tail" $ctx DELTA`. After any of those
    helpers, reload `ctx.data`, `ctx.data_meta`, and `ctx.data_end`
    before reading packet bytes again.
    `tc`, `sk_skb`, and `sk_skb_parser` also model skb packet-edit
    helpers such as `bpf_skb_store_bytes`, `bpf_l3_csum_replace`,
    `bpf_l4_csum_replace`, `bpf_get_hash_recalc`, `bpf_csum_update`,
    `bpf_set_hash_invalid`, `bpf_skb_pull_data`, `bpf_skb_change_head`,
    `bpf_skb_change_tail`, and `bpf_skb_adjust_room`. Reload `ctx.data`
    and `ctx.data_end` after `bpf_skb_pull_data`, `bpf_skb_change_head`,
    `bpf_skb_change_tail`, or `bpf_skb_adjust_room` before reading
    packet bytes again.
    `helper-call "bpf_redirect_peer" IFINDEX FLAGS` is modeled on
    `tc:...:ingress` and also requires `FLAGS = 0`.
    `helper-call "bpf_redirect_neigh" IFINDEX 0 0 0` is modeled on tc
    paths for the default neighbor-resolution form. Raw numeric return
    codes still work. Packet reads currently support scalar byte access
    through `get`/indexing, direct `u16be`/`u32be` cell-path scalar loads,
    and typed header views `eth`, `ipv4`, `ipv6`, `icmp`, `icmpv6`, `udp`,
    and `tcp`. On `xdp`, `tc`, `sk_skb`, and `sk_skb_parser`, those same
    scalar/header paths are also writable after shadowing the closure
    parameter as mutable, for example `mut ctx = $ctx; $ctx.data.0 = 0xff`,
    `mut ctx = $ctx; $ctx.data.u16be.6 = 0x86dd`, or
    `mut ctx = $ctx; $ctx.data.eth.ethertype = 0x86dd`. These lower to
    guarded packet stores and automatically normalize big-endian packet
    scalars back to network byte order. Other packet families remain
    read-only for direct packet writes. Those views also support `payload`
    stepping: `eth.payload` skips Ethernet and up to two stacked VLAN tags
    when present, `ipv4.payload` uses the runtime IHL, `ipv6.payload`
    skips the fixed IPv6 header, `icmp.payload` / `icmpv6.payload` skip
    the fixed 8-byte ICMP header, and `tcp.payload` uses the runtime data
    offset. IPv4/TCP options, ICMP subtype-specific body decoding, and
    IPv6 extension headers are still not modeled.

  perf_event targets:
    {|ctx| $ctx.cpu }    - Get current CPU ID for the sampled event
    {|ctx| $ctx.ktime }  - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.pid }    - Get current thread ID at sample time
    {|ctx| $ctx.comm }   - Get current command name at sample time
    {|ctx| $ctx.arg0 }   - Get sampled ABI register slot 0 from the saved pt_regs frame
    {|ctx| $ctx.sample_period } - Get the sampled perf period (x86_64)
    {|ctx| $ctx.addr }   - Get the sampled address, when present (x86_64)
    Note: initial perf_event support covers software `cpu-clock`,
    `task-clock`, `context-switches`, `cpu-migrations`, `page-faults`,
    `minor-faults`, and `major-faults`, plus hardware `cpu-cycles`,
    `instructions`, `cache-references`, `cache-misses`,
    `branch-instructions`, `branch-misses`, `bus-cycles`,
    `stalled-cycles-frontend`, `stalled-cycles-backend`, and
    `ref-cpu-cycles` through specs like `perf_event:software:cpu-clock`
    or `perf_event:hardware:cpu-cycles`, with optional selectors `cpu=N`,
    `pid=N`, `period=N`, or `freq=N`. Omitting the sample policy defaults
    to `period=1000000`, and omitting `cpu=` attaches on all online CPUs.

  socket_filter targets:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get packet length from `skb->len`
    {|ctx| $ctx.data }    - Get packet data pointer
    {|ctx| $ctx.data_end } - Get packet end pointer
    {|ctx| $ctx.ingress_ifindex } - Get the skb ifindex
    Note: the initial socket_filter surface uses targets like
    `socket_filter:udp4:127.0.0.1:31337`, `socket_filter:udp6:[::1]:31337`,
    `socket_filter:tcp4:127.0.0.1:31337`, or `socket_filter:tcp6:[::1]:31337`,
    which create and hold open a bound socket while the program is attached.
    Return values are snapshot lengths: `0` drops the packet,
    positive values keep it, and aliases like `pass` / `keep` expand to
    `ctx.packet_len`.

  lirc_mode2 fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.sample }  - Get the raw LIRC mode2 sample word
    {|ctx| $ctx.raw }     - Alias for the raw LIRC mode2 sample word
    {|ctx| $ctx.value }   - Get the low 24-bit LIRC payload value
    {|ctx| $ctx.mode }    - Get the high-byte LIRC event kind mask
    Note: lirc_mode2 targets use device paths such as `/dev/lirc0`. The
    initial surface is read-only and exposes the raw mode2 sample layout,
    where `ctx.mode` corresponds to constants like `LIRC_MODE2_PULSE` and
    `ctx.value` is the low 24-bit duration/frequency payload.

  lsm targets:
    {|ctx| $ctx.pid }    - Get current thread ID at hook time
    {|ctx| $ctx.comm }   - Get current command name at hook time
    {|ctx| $ctx.arg.file }   - Get a named BTF-typed LSM hook argument
    {|ctx| $ctx.arg.file.f_flags } - Project through named BTF-backed LSM hook arguments
    Note: initial LSM support uses `lsm:<hook_name>` targets such as
    `lsm:file_open`. Live loading requires a kernel with BPF LSM enabled;
    `--dry-run` is the safest way to validate object construction and BTF
    argument access on a development machine.

  cgroup_sysctl fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.write }   - Get whether the sysctl knob is being written (`1`) or read (`0`)
    {|ctx| $ctx.file_pos } - Get the current sysctl file position
    Note: cgroup_sysctl closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes.

  cgroup_sock fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.sk.family } - Project the current socket through a typed bpf_sock pointer (fields include bound_dev_if, family, type, protocol, mark, priority, src_ip4, src_ip6, src_port, dst_port, dst_ip4, dst_ip6, state, and rx_queue_mapping)
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.sock_type } - Get socket type
    {|ctx| $ctx.protocol } - Get socket protocol
    {|ctx| $ctx.bound_dev_if } - Get the bound device ifindex
    {|ctx| $ctx.mark }    - Get the socket mark
    {|ctx| $ctx.priority } - Get the socket priority
    {|ctx| $ctx.socket_cookie } - Get the stable socket cookie for the current socket context
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current socket context
    Note: cgroup_sock closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes. Initial support covers `sock_create`,
    `sock_release`, `post_bind4`, and `post_bind6` with the scalar fields
    above. On `cgroup_sock`, socket-address projection fields through
    `ctx.sk` such as `ctx.sk.src_port` and `ctx.sk.dst_port` are only
    available on `post_bind4` and `post_bind6`.

  cgroup_device fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.access_type } - Get the encoded device access type
    {|ctx| $ctx.major }   - Get the requested device major number
    {|ctx| $ctx.minor }   - Get the requested device minor number
    Note: cgroup_device closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes. `ctx.access_type` is the raw kernel encoding
    `(BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*`.

  sock_ops fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.op }      - Get the sock_ops callback opcode
    {|ctx| $ctx.args }    - Get the four sock_ops callback argument words as a fixed array
    {|ctx| mut ctx = $ctx; $ctx.reply = 1; 1 } - Write the raw sock_ops reply word through ordinary assignment
    {|ctx| mut ctx = $ctx; $ctx.replylong.0 = 7; 1 } - Write a raw replylong u32 word through ordinary assignment
    {|ctx| $ctx.packet_len } - Get the packet length when packet metadata is available
    {|ctx| $ctx.data }    - Get the packet data pointer when packet metadata is available
    {|ctx| $ctx.data_end } - Get the packet end pointer when packet metadata is available
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    {|ctx| $ctx.socket_cookie } - Get the stable socket cookie for the current sock_ops context
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current sock_ops context
    {|ctx| $ctx.is_fullsock } - Get whether the context has a full socket
    {|ctx| $ctx.snd_cwnd } - Get the current sending congestion window
    {|ctx| $ctx.srtt_us }  - Get the smoothed RTT in microseconds shifted by 3
    {|ctx| $ctx.cb_flags } - Get requested sock_ops callback flags
    {|ctx| $ctx.state }   - Get the current TCP state
    {|ctx| $ctx.rtt_min } - Get the minimum observed RTT in microseconds
    {|ctx| $ctx.snd_ssthresh } - Get the current slow-start threshold
    {|ctx| $ctx.rcv_nxt } - Get the next expected receive sequence number
    {|ctx| $ctx.snd_nxt } - Get the next send sequence number
    {|ctx| $ctx.snd_una } - Get the oldest unacknowledged send sequence number
    {|ctx| $ctx.mss_cache } - Get the current cached MSS
    {|ctx| $ctx.ecn_flags } - Get the current ECN/TCP option flags
    {|ctx| $ctx.rate_delivered } - Get the recent delivered-packet rate sample numerator
    {|ctx| $ctx.rate_interval_us } - Get the delivery-rate sampling interval in microseconds
    {|ctx| $ctx.packets_out } - Get the number of outstanding packets
    {|ctx| $ctx.retrans_out } - Get the number of retransmitted outstanding packets
    {|ctx| $ctx.total_retrans } - Get the total retransmission count
    {|ctx| $ctx.segs_in } - Get the total inbound segment count
    {|ctx| $ctx.data_segs_in } - Get the total inbound data-segment count
    {|ctx| $ctx.segs_out } - Get the total outbound segment count
    {|ctx| $ctx.data_segs_out } - Get the total outbound data-segment count
    {|ctx| $ctx.lost_out } - Get the current lost-out packet estimate
    {|ctx| $ctx.sacked_out } - Get the current SACKed-out packet estimate
    {|ctx| $ctx.sk_txhash } - Get the socket transmit hash
    {|ctx| $ctx.bytes_received } - Get the total received byte count
    {|ctx| $ctx.bytes_acked } - Get the total acknowledged byte count
    {|ctx| $ctx.skb_len } - Get the total packet length when packet metadata is available
    {|ctx| $ctx.skb_tcp_flags } - Get packet TCP flags when packet metadata is available
    {|ctx| $ctx.skb_hwtstamp } - Get packet hardware timestamp when packet metadata is available
    {|ctx| $ctx.sk.family } - Project the current socket through a typed bpf_sock pointer (fields include bound_dev_if, family, type, protocol, mark, priority, src_ip4, src_ip6, src_port, dst_port, dst_ip4, dst_ip6, state, and rx_queue_mapping)
    Note: sock_ops uses raw integer return codes. Observation-only examples
    should return `1`. `ctx.reply` and `ctx.replylong.<0-3>` are writable raw
    `u32` words after shadowing the immutable closure parameter as mutable, for
    example `mut ctx = $ctx; $ctx.reply = 1`. IPv6 addresses are
    exposed as fixed arrays of four host-order u32 words, for example
    `($ctx.remote_ip6 | get 3)`. `ctx.args` uses the same fixed-array model,
    for example `($ctx.args | get 0)`. `ctx.data` / `ctx.data_end` use the
    same guarded packet access model as XDP and tc when packet metadata is
    available, so forms like `($ctx.data | get 0)` are valid on packet-aware
    sock_ops callbacks. `ctx.sk` uses the same typed `bpf_sock` projection
    model as `cgroup_sock`, `cgroup_sockopt`, `cgroup_sock_addr`, `sk_lookup`,
    and `sk_msg`. Modeled sock_ops helpers also use the ordinary helper
    surface here, including `bpf_getsockopt`, `bpf_setsockopt`,
    `bpf_sock_ops_cb_flags_set`, and the TCP header-option helpers
    `bpf_load_hdr_opt`, `bpf_store_hdr_opt`, and `bpf_reserve_hdr_opt`.
    The compiler currently models the sock_ops program surface plus
    pointer/size and zero-flag constraints for those header-option helpers,
    while callback-op-specific verifier restrictions still remain kernel-enforced.

  sk_msg fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get total message size in bytes
    {|ctx| $ctx.data }    - Get the packet/message data pointer
    {|ctx| $ctx.data_end } - Get the end pointer for packet/message access
    {|ctx| $ctx.sk.family } - Project the current socket through a typed bpf_sock pointer (fields include bound_dev_if, family, type, protocol, mark, priority, src_ip4, src_ip6, src_port, dst_port, dst_ip4, dst_ip6, state, and rx_queue_mapping)
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current sk_msg context
    Note: sk_msg programs attach to a pinned sockmap or sockhash path such as
    `/sys/fs/bpf/demo_sockmap`. Initial sk_msg support is read-only and uses
    raw integer verdict codes; observation-only examples should return `pass`
    or `1`. `ctx.data` / `ctx.data_end` use the same guarded packet access
    model as XDP and tc, so forms like `($ctx.data | get 0)` are valid. IPv6
    addresses are exposed as fixed arrays of four host-order u32 words, for
    example `($ctx.remote_ip6 | get 3)`. Modeled socket-message helpers are
    also available through the ordinary helper surface, for example
    `helper-call "bpf_msg_apply_bytes" $ctx 8` or
    `helper-call "bpf_msg_cork_bytes" $ctx 8`, plus range/data reshaping
    helpers such as `helper-call "bpf_msg_pull_data" $ctx 0 8 0` and
    `helper-call "bpf_msg_push_data" $ctx 0 8 0` or
    `helper-call "bpf_msg_pop_data" $ctx 0 8 0`. After
    `bpf_msg_pull_data`, reload `ctx.data` and `ctx.data_end` before
    reading packet bytes again. Socket-pointer helpers whose program
    surface includes `sk_msg` are also available on `ctx.sk` after a null
    check, for example
    `if $ctx.sk != 0 { helper-call "bpf_sk_fullsock" $ctx.sk }`.

  sk_skb fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get total packet length in bytes
    {|ctx| $ctx.pkt_type } - Get the skb pkt_type
    {|ctx| $ctx.queue_mapping } - Get the skb queue_mapping
    {|ctx| $ctx.eth_protocol } - Get the skb protocol / ethertype in host byte order
    {|ctx| $ctx.vlan_present } - Get whether skb VLAN metadata is present
    {|ctx| $ctx.vlan_tci } - Get the skb VLAN TCI
    {|ctx| $ctx.vlan_proto } - Get the skb VLAN ethertype in host byte order
    {|ctx| $ctx.cb } - Get the skb cb words as a fixed array
    {|ctx| $ctx.tc_classid } - Get the skb tc_classid
    {|ctx| $ctx.napi_id } - Get the skb napi_id
    {|ctx| $ctx.wire_len } - Get the skb wire_len
    {|ctx| $ctx.gso_segs } - Get the skb gso_segs
    {|ctx| $ctx.gso_size } - Get the skb gso_size
    {|ctx| $ctx.hwtstamp } - Get the skb hardware timestamp
    {|ctx| $ctx.data }    - Get the packet data pointer
    {|ctx| $ctx.data_end } - Get the end pointer for packet access
    {|ctx| $ctx.ingress_ifindex } - Get the ingress interface index
    {|ctx| $ctx.ifindex } - Get the skb ifindex
    {|ctx| $ctx.tc_index } - Get the skb tc_index
    {|ctx| $ctx.hash }    - Get the skb hash
    {|ctx| $ctx.mark }    - Get the skb mark
    {|ctx| $ctx.priority } - Get the skb priority
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    Note: initial sk_skb support targets pinned sockmap or sockhash paths such
    as `/sys/fs/bpf/demo_sockmap` and emits `sk_skb/stream_verdict` programs.
    It uses raw verdict codes but supports `pass` / `drop` aliases, and
    `ctx.data` / `ctx.data_end` use the same guarded packet access model as
    tc and cgroup_skb. Modeled skb packet-edit helpers also use the
    ordinary helper surface here, including `bpf_skb_store_bytes`,
    `bpf_l3_csum_replace`, `bpf_l4_csum_replace`,
    `bpf_get_hash_recalc`, `bpf_csum_update`, `bpf_set_hash_invalid`,
    `bpf_skb_pull_data`, `bpf_skb_change_head`, `bpf_skb_change_tail`,
    and `bpf_skb_adjust_room`. Reload `ctx.data` and `ctx.data_end`
    after `bpf_skb_pull_data`, `bpf_skb_change_head`,
    `bpf_skb_change_tail`, or `bpf_skb_adjust_room` before reading
    packet bytes again. IPv4 addresses and the remote port are
    normalized to host byte order, and IPv6 addresses are exposed as
    four host-order u32 words for ordinary Nushell indexing.

  sk_skb_parser fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get total packet length in bytes
    {|ctx| $ctx.pkt_type } - Get the skb pkt_type
    {|ctx| $ctx.queue_mapping } - Get the skb queue_mapping
    {|ctx| $ctx.eth_protocol } - Get the skb protocol / ethertype in host byte order
    {|ctx| $ctx.vlan_present } - Get whether skb VLAN metadata is present
    {|ctx| $ctx.vlan_tci } - Get the skb VLAN TCI
    {|ctx| $ctx.vlan_proto } - Get the skb VLAN ethertype in host byte order
    {|ctx| $ctx.cb } - Get the skb cb words as a fixed array
    {|ctx| $ctx.tc_classid } - Get the skb tc_classid
    {|ctx| $ctx.napi_id } - Get the skb napi_id
    {|ctx| $ctx.wire_len } - Get the skb wire_len
    {|ctx| $ctx.gso_segs } - Get the skb gso_segs
    {|ctx| $ctx.gso_size } - Get the skb gso_size
    {|ctx| $ctx.hwtstamp } - Get the skb hardware timestamp
    {|ctx| $ctx.data }    - Get the packet data pointer
    {|ctx| $ctx.data_end } - Get the end pointer for packet access
    {|ctx| $ctx.ingress_ifindex } - Get the ingress interface index
    {|ctx| $ctx.ifindex } - Get the skb ifindex
    {|ctx| $ctx.tc_index } - Get the skb tc_index
    {|ctx| $ctx.hash }    - Get the skb hash
    {|ctx| $ctx.mark }    - Get the skb mark
    {|ctx| $ctx.priority } - Get the skb priority
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    Note: initial sk_skb_parser support targets pinned sockmap or sockhash
    paths such as `/sys/fs/bpf/demo_sockmap` and emits `sk_skb/stream_parser`
    programs. It uses raw integer parser returns rather than verdict aliases,
    so ordinary examples should return an integer such as `0` or
    `$ctx.packet_len`. Modeled skb packet-edit helpers also use the
    ordinary helper surface here, including `bpf_skb_store_bytes`,
    `bpf_l3_csum_replace`, `bpf_l4_csum_replace`,
    `bpf_get_hash_recalc`, `bpf_csum_update`, `bpf_set_hash_invalid`,
    `bpf_skb_pull_data`, `bpf_skb_change_head`, `bpf_skb_change_tail`,
    and `bpf_skb_adjust_room`. Reload `ctx.data` and `ctx.data_end`
    after `bpf_skb_pull_data`, `bpf_skb_change_head`,
    `bpf_skb_change_tail`, or `bpf_skb_adjust_room` before reading
    packet bytes again. IPv4 addresses and the remote port are
    normalized to host byte order, and IPv6 addresses are exposed as
    four host-order u32 words for ordinary Nushell indexing.

  cgroup_sockopt fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.sk.family } - Project the current socket through a typed bpf_sock pointer (fields include bound_dev_if, family, type, protocol, mark, priority, src_ip4, src_ip6, src_port, dst_port, dst_ip4, dst_ip6, state, and rx_queue_mapping)
    {|ctx| $ctx.level }   - Get the socket-option level
    {|ctx| $ctx.optname } - Get the socket-option name
    {|ctx| $ctx.optlen }  - Get the socket-option length
    {|ctx| $ctx.optval }  - Get the kernel pointer to the sockopt buffer
    {|ctx| $ctx.optval_end } - Get the end pointer for the sockopt buffer
    {|ctx| $ctx.sockopt_retval } - Get the getsockopt return value on `cgroup_sockopt:get`
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current socket context
    Note: cgroup_sockopt closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes. `optval` / `optval_end` are surfaced as kernel
    pointers, so existing pointer reads like `($ctx.optval | get 0)` or
    `read-kernel-str` can inspect buffer contents. `ctx.sk` uses the same
    typed `bpf_sock` projection model as `cgroup_sock`, `sk_lookup`, and
    `sk_msg`. Modeled socket-option helpers are also available through the
    ordinary helper surface here, including `bpf_getsockopt` and
    `bpf_setsockopt` on the current sockopt context. On `cgroup_sockopt:get`,
    writable return overrides use ordinary assignment through a mutable local
    alias such as `mut ctx = $ctx; $ctx.sockopt_retval = 0`.

  cgroup_sock_addr fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.socket_cookie } - Get the stable socket cookie for the current socket context
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current socket context
    {|ctx| $ctx.user_family } - Get userspace-requested socket family
    {|ctx| $ctx.user_ip4 } - Get the IPv4 destination/source address in host byte order on *4 hooks
    {|ctx| $ctx.user_ip6 } - Get the IPv6 destination/source address as four host-order u32 words on *6 hooks
    {|ctx| $ctx.user_port } - Get the requested port in host byte order
    {|ctx| $ctx.family }  - Get kernel socket family
    {|ctx| $ctx.sock_type } - Get socket type
    {|ctx| $ctx.protocol } - Get socket protocol
    {|ctx| $ctx.sk.family } - Project the current socket through a typed bpf_sock pointer (fields include bound_dev_if, family, type, protocol, mark, priority, src_ip4, src_ip6, src_port, dst_port, dst_ip4, dst_ip6, state, and rx_queue_mapping)
    {|ctx| $ctx.msg_src_ip4 } - Get the IPv4 source address in host byte order on sendmsg4/recvmsg4
    {|ctx| $ctx.msg_src_ip6 } - Get the IPv6 source address as four host-order u32 words on sendmsg6/recvmsg6
    Note: cgroup_sock_addr closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes. This initial slice still exposes IPv6
    addresses as fixed arrays of four u32 words rather than a higher-level
    address type. `ctx.sk` uses the same typed `bpf_sock` projection model as
    `cgroup_sock`, `cgroup_sockopt`, `sock_ops`, `sk_lookup`, and `sk_msg`.
    Modeled socket helpers are available through the ordinary helper surface:
    `bpf_bind` on `connect4` / `connect6`, and `bpf_getsockopt` /
    `bpf_setsockopt` on the current `bind*`, `connect*`, `getpeername*`,
    `getsockname*`, `sendmsg*`, and `recvmsg*` hooks.

  sk_lookup fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.sk.bound_dev_if } - Project the selected socket through a typed bpf_sock pointer (fields include bound_dev_if, family, type, protocol, mark, priority, src_ip4, src_ip6, src_port, dst_port, dst_ip4, dst_ip6, state, and rx_queue_mapping)
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.protocol } - Get IP protocol
    {|ctx| $ctx.cookie }  - Get the socket lookup cookie
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    {|ctx| $ctx.ingress_ifindex } - Get the arriving ingress interface index
    Note: sk_lookup closures can return `pass` or `drop` instead of raw
    `1`/`0` result codes. `allow` / `deny` aliases also work. IPv6
    addresses are exposed as fixed arrays of four host-order u32 words, so
    normal Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`.

  Function fields:
    {|ctx| $ctx.arg0 }    - Get function argument 0
    {|ctx| $ctx.arg1 }    - Get function argument 1
    {|ctx| $ctx.retval }  - Get return value (kretprobe/uretprobe/fexit)

    Note: kprobe/uprobe expose pt_regs-style ctx.arg0-5. raw_tracepoint exposes
    raw positional ctx.argN slots. fentry/fexit/tp_btf/lsm/struct_ops use
    kernel BTF, and those kernel-BTF-backed contexts also expose named
    parameter aliases through ctx.arg.<name> when names are available.
    Scalar/pointer trampoline args and returns work directly. By-value
    trampoline args and pointer-backed trampoline args/returns
    support scalar/pointer field projection like ctx.arg0.some_field.
    Pointer-backed projections use null-guarded bpf_probe_read_{kernel,user}
    and can cross intermediate and repeated pointer hops like ctx.arg0.foo.bar
    or ctx.arg0.fdt.fd.f_inode.i_ino. Fixed-size arrays can be indexed with
    numeric path segments like ctx.arg0.comm.0, and pointer-backed sequences
    can now also be indexed with constant numeric segments such as
    `ctx.arg0.fdt.fd.0.f_inode.i_ino` or `let fd = $ctx.arg0.fdt.fd;
    $fd.0.f_inode.i_ino`. Numeric `get` now supports the same typed
    kernel/user pointer traversal through a register value, and also supports
    stack-backed fixed arrays such as `let idx = ($ctx.pid mod 2);
    ($ctx.arg0.comm | get $idx)`. Pointer-valued examples include
    `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`.
    Bounded ascending `for` loops over static integer ranges now lower to
    verifier-safe loops, so `for i in 0..0 { ... get $i ... }` works.
    Bounded arithmetic on those indices, such as
    `let j = (($i + 1) mod 2)`, is preserved too. The same range tracking
    now works for typed unsigned runtime fields such as
    `let idx = ($ctx.arg0.fdt.max_fds mod 2)`. Branch-sensitive narrowing
    also works for both bound and repeated direct paths, for example
    `let max = $ctx.arg0.fdt.max_fds; if $max > 0 { let idx = ($max - 1);
    ... }` or `if $ctx.arg0.fdt.max_fds > 0 { let idx =
    ($ctx.arg0.fdt.max_fds - 1); ... }`. Descending ranges are still
    rejected. Typed BTF bitfields are also projected through those same
    paths, including after numeric `get`, for example `let idx =
    ($ctx.pid mod 2); let clamp = ($ctx.arg0.uclamp_req | get $idx);
    $clamp.value`.
    Terminal array leaves and unsupported aggregate leaves are exposed as
    stack-backed byte buffers. Representable terminal struct leaves keep their
    field layouts, including BTF bitfield members, for count/counter decoding,
    and single-value emit can now stream those struct leaves as records.
    Nested array/record fields inside emitted values also decode recursively
    when the compiler can preserve their layouts. emit still preserves
    unsupported aggregate layouts as binary payloads, and count can use them
    as byte-buffer keys. ebpf counters decodes those keys using any schema the
    compiler still has: arrays and typed structs can surface as strings,
    lists, or records; opaque aggregate layouts still display as binary. Plain
    positional ctx.argN and ctx.retval loads also preserve their typed pointer
    or aggregate layouts
    across bindings, for example `let files = $ctx.arg0;
    $files.fdt.fd.f_inode.i_ino` or `let inode = $ctx.arg0.f_inode;
    $inode.i_sb.s_flags`. Kernel-BTF-backed contexts also expose named
    parameter names through `ctx.arg.<name>`, for example
    `ctx.arg.prev_cpu`, `ctx.arg.p.pid`, or `ctx.arg.file.f_flags`.
    16-byte byte-array/string keys such as ctx.arg0.comm continue to display
    as strings.
    Aggregate fexit returns still depend on kernel trampoline support;
    some kernels reject struct returns entirely.

  Tracepoint fields:
    Access fields specific to each tracepoint. Fields are read from tracefs.
    Example for syscalls/sys_enter_openat:
      {|ctx| $ctx.dfd }      - Directory file descriptor
      {|ctx| $ctx.filename } - Pointer to filename string
      {|ctx| $ctx.flags }    - Open flags

Output commands:
  emit              - Send value to userspace via ring buffer
  read-str          - Read string from userspace memory pointer
  read-kernel-str   - Read string from kernel memory (rare)
  global-define     - Declare a named compiler-managed program global
  global-get        - Load a named compiler-managed program global
  global-set        - Store the pipeline input into a named compiler-managed program global

Globals:
  Prefer leading annotated `mut` bindings for small private program state:
    {|ctx| mut state: int = 0; $state = ($state + 1); $state | count }
  The initializer must currently be a compile-time constant.

Aggregation commands:
  count             - Count occurrences by key
  histogram         - Add value to log2 histogram

Timing commands:
  start-timer       - Record timestamp (use with --pin for cross-probe timing)
  stop-timer        - Calculate elapsed nanoseconds since start-timer

Advanced commands:
  helper-call       - Call a modeled BPF helper by name
  kfunc-call        - Call a typed kernel kfunc by name (optional --btf-id)
  map-push          - Push into a named queue or stack map (--kind queue|stack)
  map-peek          - Peek the next queue/stack value as a maybe-null pointer
  map-pop           - Pop the next queue/stack value as a maybe-null pointer

Flags:
  --stream (-s)     Stream events in real-time. The command blocks and yields
                    events as they occur. Use Ctrl-C to stop, or pipe to
                    `first N` to capture a fixed number of events.

  --dry-run (-n)    Generate eBPF bytecode without loading into kernel.
                    Returns the compiled ELF binary. Useful for:
                    - Debugging compilation issues
                    - Inspecting generated bytecode (pipe to `save prog.o`)
                    - Validating closures before deployment

  --unsafe-struct-ops
                    Allow live loading of high-risk struct_ops families such as
                    `sched_ext_ops`. Prefer `--dry-run` on the host and use a VM
                    or disposable environment before enabling this.

  --pin (-p) GROUP  Pin maps to /sys/fs/bpf/nushell/GROUP/ for sharing between
                    probes. Essential for timing measurements where kprobe and
                    kretprobe need to share the timestamp map:

                    let entry = ebpf attach --pin timing 'kprobe:vfs_read' {
                        start-timer
                    }
                    let exit = ebpf attach --pin timing 'kretprobe:vfs_read' {
                        stop-timer | histogram
                    }

                    Maps are automatically unpinned when all probes detach.

Limits:
  - eBPF stack: 512 bytes (complex closures may overflow)
  - String reads: 128 bytes max (longer strings truncated)
  - Map entries: 10,240 max per map (count, histogram, timers)
  - Ring buffer: 256 KB (high event rates may drop events)
  - Stack traces: 127 frames max

Discovering tracepoints:
  ls /sys/kernel/tracing/events/              # List categories
  ls /sys/kernel/tracing/events/syscalls/     # List syscall tracepoints
  cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format  # View fields

Requirements:
  - Linux kernel 4.18+ for the basic tracing paths
  - Linux kernel 5.5+ with /sys/kernel/btf/vmlinux for fentry/fexit
  - CAP_BPF + CAP_PERFMON capabilities, or root access
  - Run `ebpf setup` to configure capabilities"#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf attach")
            .input_output_types(vec![
                (Type::Nothing, Type::Int),     // Returns probe ID (default)
                (Type::Nothing, Type::Binary),  // Returns ELF with --dry-run
                (Type::Nothing, Type::table()), // Streams events with --stream
            ])
            .required(
                "probe",
                SyntaxShape::String,
                "The probe point (e.g., 'kprobe:sys_clone', 'xdp:lo', 'socket_filter:udp4:127.0.0.1:31337', 'socket_filter:udp6:[::1]:31337', 'socket_filter:tcp4:127.0.0.1:31337', 'socket_filter:tcp6:[::1]:31337', 'cgroup_skb:/sys/fs/cgroup:egress', 'cgroup_device:/sys/fs/cgroup', 'cgroup_sock:/sys/fs/cgroup:sock_create', 'sock_ops:/sys/fs/cgroup', 'sk_msg:/sys/fs/bpf/demo_sockmap', 'sk_skb:/sys/fs/bpf/demo_sockmap', 'sk_skb_parser:/sys/fs/bpf/demo_sockmap', 'cgroup_sysctl:/sys/fs/cgroup', 'cgroup_sockopt:/sys/fs/cgroup:get', 'cgroup_sock_addr:/sys/fs/cgroup:connect4', 'sk_lookup:/proc/self/ns/net', or 'lirc_mode2:/dev/lirc0').",
            )
            .required(
                "body",
                SyntaxShape::Any,
                "Closure body for ordinary attach types, or a record of constant fields and optional callback closures for struct_ops.",
            )
            .switch(
                "stream",
                "Stream events directly (Ctrl-C to stop)",
                Some('s'),
            )
            .switch(
                "dry-run",
                "Generate bytecode but don't load into kernel",
                Some('n'),
            )
            .switch(
                "unsafe-struct-ops",
                "Allow live loading of high-risk struct_ops families such as sched_ext_ops",
                None,
            )
            .named(
                "pin",
                SyntaxShape::String,
                "Pin maps to share between probes (e.g., --pin mygroup)",
                Some('p'),
            )
            .category(Category::Experimental)
    }

    fn search_terms(&self) -> Vec<&str> {
        vec![
            "bpf",
            "kernel",
            "trace",
            "probe",
            "kprobe",
            "fentry",
            "fexit",
            "tp_btf",
            "tracepoint",
            "uprobe",
            "uretprobe",
            "userspace",
            "perf_event",
            "socket_filter",
            "xdp",
            "tc",
            "cgroup_skb",
            "cgroup_device",
            "cgroup_sock",
            "sock_ops",
            "sk_msg",
            "sk_skb",
            "sk_skb_parser",
            "cgroup_sysctl",
            "cgroup_sockopt",
            "cgroup_sock_addr",
            "sk_lookup",
            "lirc_mode2",
            "struct_ops",
        ]
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach --stream 'kprobe:sys_clone' {|ctx| $ctx.pid | emit }",
                description: "Stream events from sys_clone (Ctrl-C to stop)",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.tgid | emit } | first 10",
                description: "Capture first 10 sys_read events",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'tracepoint:syscalls/sys_enter_openat' {|ctx| $ctx.filename | emit }",
                description: "Stream filenames from openat syscalls using tracepoint",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'fentry:security_file_open' {|ctx| $ctx.arg.file.f_flags | emit } | first 5",
                description: "Capture the first 5 fentry file flags using a named BTF-backed trampoline arg",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'fexit:ksys_read' {|ctx| $ctx.retval | emit } | first 5",
                description: "Capture the first 5 fexit return values using BTF-backed trampolines",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'tp_btf:sys_enter' {|ctx| $ctx.arg.regs.orig_ax | count; 0 }",
                description: "Dry-run a BTF-enabled raw tracepoint using typed trampoline args",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'lsm:file_open' {|ctx| $ctx.arg.file.f_flags | count; 0 }",
                description: "Dry-run an LSM file_open hook using BTF-backed hook arguments",
                result: None,
            },
            Example {
                example: "ebpf attach 'perf_event:software:cpu-clock:period=100000' {|ctx| $ctx.cpu | count; 0 }",
                description: "Count software cpu-clock samples by CPU",
                result: None,
            },
            Example {
                example: "ebpf attach 'perf_event:software:cpu-clock:period=100000' {|ctx| $ctx.arg0 | count; 0 }",
                description: "Count software cpu-clock samples by sampled pt_regs arg0 register",
                result: None,
            },
            Example {
                example: "ebpf attach 'perf_event:software:cpu-clock:period=100000' {|ctx| $ctx.sample_period | count; 0 }",
                description: "Count software cpu-clock samples by sampled period (x86_64)",
                result: None,
            },
            Example {
                example: "ebpf attach 'socket_filter:udp4:127.0.0.1:31337' {|ctx| $ctx.packet_len | count; 'pass' }",
                description: "Count loopback UDP packet lengths on a bound socket_filter receive socket",
                result: None,
            },
            Example {
                example: "ebpf attach 'socket_filter:udp6:[::1]:31337' {|ctx| $ctx.packet_len | count; 'pass' }",
                description: "Count loopback UDPv6 packet lengths on a bound socket_filter receive socket",
                result: None,
            },
            Example {
                example: "ebpf attach 'socket_filter:tcp4:127.0.0.1:31337' {|ctx| $ctx.packet_len | count; 'pass' }",
                description: "Count loopback TCP packet lengths on a bound socket_filter listener",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_skb:/sys/fs/cgroup:egress' {|ctx| $ctx.packet_len | count; 'allow' }",
                description: "Count packet lengths on cgroup egress traffic",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_device:/sys/fs/cgroup' {|ctx| $ctx.major | count; 'allow' }",
                description: "Count device major numbers requested by processes in a cgroup",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sock:/sys/fs/cgroup:sock_create' {|ctx| $ctx.family | count; 'allow' }",
                description: "Count socket families at cgroup socket-create time",
                result: None,
            },
            Example {
                example: "ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| $ctx.op | count; 1 }",
                description: "Count sock_ops callback opcodes on TCP socket events in a cgroup",
                result: None,
            },
            Example {
                example: "ebpf attach 'sk_msg:/sys/fs/bpf/demo_sockmap' {|ctx| ($ctx.data | get 0) | count; 'pass' }",
                description: "Count first-byte observations on a pinned sockmap or sockhash sk_msg verdict hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'sk_skb:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.local_port | count; 'pass' }",
                description: "Count packet lengths on a pinned sockmap or sockhash sk_skb stream-verdict hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'sk_skb_parser:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.local_port | count; 0 }",
                description: "Count packet lengths on a pinned sockmap or sockhash sk_skb stream-parser hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sysctl:/sys/fs/cgroup' {|ctx| $ctx.write | count; 'allow' }",
                description: "Count sysctl reads versus writes on a cgroup sysctl hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sockopt:/sys/fs/cgroup:get' {|ctx| $ctx.optname | count; 'allow' }",
                description: "Count getsockopt option names on a cgroup socket-option hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sock_addr:/sys/fs/cgroup:connect4' {|ctx| $ctx.user_port | count; 'allow' }",
                description: "Count requested ports on cgroup connect4 hooks",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sock_addr:/sys/fs/cgroup:connect6' {|ctx| ($ctx.user_ip6 | get 3) | count; 'allow' }",
                description: "Count the last host-order IPv6 address word on cgroup connect6 hooks",
                result: None,
            },
            Example {
                example: "ebpf attach 'sk_lookup:/proc/self/ns/net' {|ctx| $ctx.local_port | count; 'pass' }",
                description: "Count local ports seen by socket lookup in the current network namespace",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'lirc_mode2:/dev/lirc0' {|ctx| $ctx.value | count; 0 }",
                description: "Dry-run a lirc_mode2 decoder using the raw mode2 sample context",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'struct_ops:sched_ext_ops' { name: 'nu_demo' }",
                description: "Build a struct_ops object from constant value fields and optional callback closures without loading it",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'struct_ops:sched_ext_ops' { name: 'nu_demo', select_cpu: {|ctx| let p = $ctx.arg.p; let prev = $ctx.arg.prev_cpu; let wake = $ctx.arg.wake_flags; let mask = (kfunc-call \"scx_bpf_get_online_cpumask\"); if $mask != 0 { let cpu = (kfunc-call \"scx_bpf_select_cpu_and\" $p $prev $wake $mask 0); kfunc-call \"scx_bpf_put_cpumask\" $mask; $cpu } else { $prev } } }",
                description: "Dry-run a sched_ext select_cpu callback with the safe cpumask acquire/use/release pattern",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'kprobe:ksys_read' {|| helper-call 'bpf_get_current_pid_tgid' | count }",
                description: "Dry-run a closure that calls a modeled BPF helper by name",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(super::linux_only_error(call.head));
        }

        #[cfg(target_os = "linux")]
        {
            run_attach(engine, call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_attach(
    engine: &EngineInterface,
    call: &EvaluatedCall,
) -> Result<PipelineData, LabeledError> {
    use crate::loader::{LoadError, ProgramSpec, get_state, parse_program_spec};

    let probe_spec: String = call.req(0)?;
    let body: Value = call.req(1)?;
    let dry_run = call.has_flag("dry-run")?;
    let stream = call.has_flag("stream")?;
    let allow_unsafe_struct_ops = call.has_flag("unsafe-struct-ops")?;
    let pin_group: Option<String> = call.get_flag("pin")?;

    // Parse the probe specification (includes validation)
    let program_spec = parse_program_spec(&probe_spec).map_err(|e| match &e {
        crate::loader::LoadError::FunctionNotFound { name, suggestions } => {
            let help = if suggestions.is_empty() {
                format!("Check the function name. Use 'sudo cat /sys/kernel/tracing/available_filter_functions | grep {name}' to find available functions.")
            } else {
                format!("Did you mean: {}?", suggestions.join(", "))
            };
            LabeledError::new(format!("Kernel function '{}' not found", name))
                .with_label("This function is not available for probing", call.head)
                .with_help(help)
        }
        crate::loader::LoadError::TracepointNotFound { category, name } => {
            LabeledError::new(format!("Tracepoint '{}/{}' not found", category, name))
                .with_label("This tracepoint does not exist", call.head)
                .with_help(format!(
                    "Use 'sudo ls /sys/kernel/tracing/events/{}' to see available tracepoints",
                    category
                ))
        }
        crate::loader::LoadError::UnsupportedTrampolineTarget {
            probe_type,
            target,
            reason,
        } => {
            let mut err =
                LabeledError::new(format!("Unsupported {} target '{}'", probe_type, target))
                    .with_label(reason.clone(), call.head);
            if let Some(help) = match probe_type.as_str() {
                "fentry" | "fexit" => Some(
                    "fentry/fexit require kernel BTF and a trampoline-compatible target signature. Try a scalar/pointer-return target or use kprobe/kretprobe for broader coverage",
                ),
                _ => None,
            } {
                err = err.with_help(help);
            }
            err
        }
        crate::loader::LoadError::NeedsSudo => {
            LabeledError::new("Elevated privileges required")
                .with_label("eBPF operations require root or CAP_BPF capability", call.head)
                .with_help("Run nushell with sudo: sudo nu")
        }
        _ => LabeledError::new("Invalid probe specification")
            .with_label(e.to_string(), call.head)
            .with_help("Use format like 'kprobe:sys_clone' or 'tracepoint:syscalls/sys_enter_read'"),
    })?;

    let object = match &program_spec {
        ProgramSpec::StructOps { value_type_name } => {
            if stream {
                return Err(LabeledError::new("Streaming is not supported for struct_ops objects")
                    .with_label(
                        "struct_ops objects currently register callbacks but cannot stream events",
                        call.head,
                    ));
            }
            if pin_group.is_some() {
                return Err(LabeledError::new(
                    "Pinned map sharing is not supported for struct_ops",
                )
                .with_label("struct_ops objects currently cannot use --pin", call.head));
            }
            validate_struct_ops_attach_safety(
                value_type_name,
                dry_run,
                allow_unsafe_struct_ops,
                call.head,
            )?;
            let record = body.into_record().map_err(|e| {
                LabeledError::new("Invalid struct_ops body")
                    .with_label(e.to_string(), call.head)
                    .with_help(
                        "Use a record whose callback fields are closures, for example { select_cpu: {|ctx| 0 } }",
                    )
            })?;
            compile_struct_ops_object(engine, value_type_name, &record, call.head)?
        }
        _ => {
            let closure = value_to_spanned_closure(body, call.head)?;
            let probe_context = ProbeContext::from_program_spec(program_spec);
            let prog_type = probe_context.program_type();
            let target = probe_context.target().to_string();
            let compiled = compile_closure_with_context(
                engine,
                &closure,
                &probe_context,
                pin_group.as_deref(),
                call.head,
            )?;
            let mut program = compiled.compile_result.into_program(
                prog_type,
                &target,
                "nushell_ebpf",
                compiled.generic_map_value_types,
                compiled.generic_map_value_semantics,
            );
            if pin_group.is_some() {
                program = program.with_pinning();
            }
            EbpfObject::single_program(program)
        }
    };

    let state = get_state();

    if dry_run {
        let elf = object.to_elf().map_err(|e| {
            LabeledError::new("Failed to generate ELF").with_label(e.to_string(), call.head)
        })?;
        return Ok(PipelineData::Value(Value::binary(elf, call.head), None));
    }

    // Load and attach
    let probe_id = state
        .attach_with_pin(&object, pin_group.as_deref())
        .map_err(|e| {
            let help = match &e {
                LoadError::PermissionDenied => {
                    Some("Try running with sudo or grant CAP_BPF capability")
                }
                _ => None,
            };
            let mut err = LabeledError::new("Failed to attach eBPF probe")
                .with_label(e.to_string(), call.head);
            if let Some(h) = help {
                err = err.with_help(h);
            }
            err
        })?;

    if stream {
        // For streaming, we return values one at a time
        // In a plugin, we can use PipelineData with an iterator
        let span = call.head;
        let iter = EventStreamIterator::new(probe_id, span);
        Ok(PipelineData::ListStream(
            nu_protocol::ListStream::new(iter, span, engine.signals().clone()),
            None,
        ))
    } else {
        Ok(PipelineData::Value(
            Value::int(probe_id as i64, call.head),
            None,
        ))
    }
}

#[cfg(test)]
mod tests;
