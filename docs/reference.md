# Language And Context Reference

Detailed reference for the current compiler surface. See the [README](../README.md) for the front-page guide and the [example gallery](examples.md) for runnable snippets.

## Context Fields

The closure receives a context parameter with these fields:

| Field | Description | Probe Types |
|-------|-------------|-------------|
| `pid` | Kernel PID / thread ID | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `tid` | Alias for `pid` | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `tgid` | Process ID (thread group) | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `pid_tgid` / `current_pid_tgid` | Packed `(tgid << 32) | pid` value from `bpf_get_current_pid_tgid` | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `uid` | User ID | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `gid` | Group ID | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `uid_gid` / `current_uid_gid` | Packed `(gid << 32) | uid` value from `bpf_get_current_uid_gid` | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `comm` | Process name (16 bytes) | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `task` / `current_task` | Current `task_struct *` pointer from `bpf_get_current_task_btf`; the legacy `bpf_get_current_task` helper is also modeled as a typed non-null task pointer. BTF-backed fields such as `task.pid` can be projected directly or after binding the pointer to a local when kernel BTF is available. On tracepoints, use `current_task` when you need the builtin rather than a payload field named `task`. | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `task` / `iter_task` | Nullable iterated `task_struct *` pointer from task-bearing iterator contexts; BTF-backed fields such as `task.pid` can be projected when kernel BTF is available. This is intentionally distinct from `current_task`. | `iter:task`, `iter:task_file`, `iter:task_vma` |
| `meta` / `iter_meta` | Non-null `bpf_iter_meta *` pointer exposed by BPF iterator contexts; BTF-backed fields such as `meta.seq_num` can be projected when kernel BTF is available. | `iter:*` |
| `fd` / `iter_fd` | File descriptor for the current `task_file` iterator element. | `iter:task_file` |
| `file` / `iter_file` | Nullable iterated `file *` pointer from `struct bpf_iter__task_file`; BTF-backed fields such as `file.f_mode` can be projected when kernel BTF is available. | `iter:task_file` |
| `vma` / `iter_vma` | Nullable iterated `vm_area_struct *` pointer from `struct bpf_iter__task_vma`; BTF-backed fields such as `vma.vm_start` can be projected when kernel BTF is available. | `iter:task_vma` |
| `cgroup` / `iter_cgroup` | Nullable iterated `cgroup *` pointer from `struct bpf_iter__cgroup`; BTF-backed fields such as `cgroup.level` can be projected when kernel BTF is available. This shadows the current-task cgroup alias only on iterator programs; use `current_cgroup` for the helper-backed current-task cgroup meaning on other tracing families. | `iter:cgroup` |
| `map` / `iter_map` | Nullable iterated `bpf_map *` pointer from BPF map iterator contexts; BTF-backed fields such as `map.id` can be projected when kernel BTF is available. | `iter:bpf_map`, `iter:bpf_map_elem`, `iter:bpf_sk_storage_map`, `iter:sockmap` |
| `key` / `iter_key` | Nullable map key pointer from BPF map-element iterator contexts. | `iter:bpf_map_elem`, `iter:sockmap` |
| `value` / `iter_value` | Nullable map value pointer from BPF map-element and BPF socket-storage iterator contexts. | `iter:bpf_map_elem`, `iter:bpf_sk_storage_map` |
| `sk` / `sock` / `iter_sock` | Nullable iterated `sock *` pointer from socket-storage-map and sockmap iterator contexts. | `iter:bpf_sk_storage_map`, `iter:sockmap` |
| `prog` / `iter_prog` | Nullable iterated `bpf_prog *` pointer from `struct bpf_iter__bpf_prog`; BTF-backed fields such as `prog.len` can be projected when kernel BTF is available. | `iter:bpf_prog` |
| `link` / `iter_link` | Nullable iterated `bpf_link *` pointer from `struct bpf_iter__bpf_link`; BTF-backed fields such as `link.id` can be projected when kernel BTF is available. | `iter:bpf_link` |
| `sk_common` / `sock_common` / `iter_sk_common` | Nullable iterated `sock_common *` pointer from `struct bpf_iter__tcp`; BTF-backed fields such as `sk_common.skc_family` can be projected when kernel BTF is available. | `iter:tcp` |
| `udp_sk` / `iter_udp_sk` | Nullable iterated `udp_sock *` pointer from `struct bpf_iter__udp`; BTF-backed fields such as `udp_sk.inet.sk.__sk_common.skc_family` can be projected when kernel BTF is available. | `iter:udp` |
| `unix_sk` / `iter_unix_sk` | Nullable iterated `unix_sock *` pointer from `struct bpf_iter__unix`; BTF-backed fields such as `unix_sk.sk.__sk_common.skc_family` can be projected when kernel BTF is available. | `iter:unix` |
| `uid` / `iter_uid` | Socket owner uid emitted by TCP, UDP, and UNIX socket iterators. | `iter:tcp`, `iter:udp`, `iter:unix` |
| `bucket` / `iter_bucket` | UDP iterator hash bucket. | `iter:udp` |
| `dmabuf` / `iter_dmabuf` | Nullable iterated `dma_buf *` pointer from `struct bpf_iter__dmabuf`. | `iter:dmabuf` |
| `rt` / `route` / `ipv6_route` / `iter_ipv6_route` | Nullable iterated `fib6_info *` pointer from `struct bpf_iter__ipv6_route`. | `iter:ipv6_route` |
| `cache` / `kmem_cache` / `iter_kmem_cache` | Nullable iterated `kmem_cache *` pointer from `struct bpf_iter__kmem_cache`. | `iter:kmem_cache` |
| `ksym` / `iter_ksym` | Nullable iterated `kallsym_iter *` pointer from `struct bpf_iter__ksym`. | `iter:ksym` |
| `netlink_sk` / `iter_netlink_sk` | Nullable iterated `netlink_sock *` pointer from `struct bpf_iter__netlink`. | `iter:netlink` |
| `cgroup` / `current_cgroup` | Current task default `cgroup *` pointer, available for cgroup-local-storage ownership and BTF-backed cgroup projections such as `current_cgroup.kn.id`; follow-up projections also work after binding the pointer to a local. On tracepoints, use `current_cgroup` when you need the builtin rather than a payload field named `cgroup`. | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, fentry, fexit, fmod_ret, tracepoint, raw_tracepoint, raw_tracepoint.w, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event |
| `cgroup_id` | Current task cgroup ID | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `ancestor_cgroup_id.N` | Current task ancestor cgroup ID at constant numeric level `N` | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `cpu` | CPU ID | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `numa_node` / `numa_node_id` | Current NUMA node ID from `bpf_get_numa_node_id` | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `random` / `prandom_u32` | Pseudo-random `u32` from `bpf_get_prandom_u32`; ordinary `random int` is preferred when it fits the expression | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `ktime` | Kernel timestamp (ns) | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `ktime_boot` | Boot-time kernel timestamp (ns, includes suspend time) | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `ktime_coarse` | Coarse kernel timestamp (ns) | non-tracing runtime-context program types such as XDP, TC/TCX/Netkit, LWT, cgroup, socket, flow dissector, netfilter, and LIRC |
| `ktime_tai` | TAI kernel timestamp (ns) | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `jiffies` | Kernel jiffies counter | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
| `func_ip` | Address of the traced function/probe target (`bpf_get_func_ip`) | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf |
| `attach_cookie` | Per-attachment cookie supplied at link/attach time (`bpf_get_attach_cookie`) | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf |
| `kstack` | Kernel stack-trace ID collected through `bpf_get_stackid` and stored in the `kstacks` stack-trace map | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf |
| `ustack` | User stack-trace ID collected through `bpf_get_stackid` and stored in the `ustacks` stack-trace map | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf |
| `sample_period` | Sample period from `bpf_perf_event_data` | perf_event (x86_64 currently) |
| `addr` | Sampled address from `bpf_perf_event_data` | perf_event (x86_64 currently) |
| `perf_counter` | Perf event counter value from `bpf_perf_prog_read_value` | perf_event |
| `perf_enabled` | Perf event enabled time from `bpf_perf_prog_read_value` | perf_event |
| `perf_running` | Perf event running time from `bpf_perf_prog_read_value` | perf_event |
| `packet_len` / `len` | Packet length (`data_end - data` on XDP, `skb->len` on skb-backed packet programs, `sk_reuseport_md.len` on sk_reuseport, `size` on sk_msg, `skb_len` on packet-aware sock_ops callbacks); `ctx.size` is also accepted on sk_msg | xdp, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `xdp_buff_len` / `xdp_buffer_len` | Total XDP buffer length from `bpf_xdp_get_buff_len`, including paged fragments | xdp |
| `pkt_type` | skb pkt_type | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `queue_mapping` | skb queue_mapping | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `eth_protocol` | skb protocol / ethertype in host byte order; `protocol` is also accepted on skb-backed packet contexts to match the kernel field name | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_reuseport, sk_skb, sk_skb_parser |
| `vlan_present` | Whether skb VLAN metadata is present | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `vlan_tci` | skb VLAN TCI | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `vlan_proto` | skb VLAN ethertype in host byte order | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `cb` | skb control-block words as five host-order `u32` values | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `tc_classid` | skb tc_classid | tc_action, tc, tcx, netkit |
| `cgroup_classid` | skb cgroup class ID from `bpf_get_cgroup_classid` | lwt_*, tc_action, netkit, tc/tcx egress |
| `route_realm` | skb route realm from `bpf_get_route_realm` | lwt_*, tc_action, netkit, tc/tcx egress |
| `csum_level` | skb checksum level query from `bpf_csum_level(..., BPF_CSUM_LEVEL_QUERY)`; returns a negative error if the kernel cannot query it | lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, sk_skb_parser |
| `skb_cgroup_id` | skb cgroup ID from `bpf_skb_cgroup_id` | tc_action, tc egress, tcx egress |
| `skb_ancestor_cgroup_id.N` | skb ancestor cgroup ID at constant numeric level `N` from `bpf_skb_ancestor_cgroup_id` | tc_action, tc egress, tcx egress |
| `napi_id` | skb napi_id | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `wire_len` | skb wire_len | tc_action, tc, tcx, netkit |
| `gso_segs` | skb GSO segment count | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `gso_size` | skb GSO segment size | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `tstamp` | skb timestamp | tc_action, tc, tcx, netkit, cgroup_skb |
| `tstamp_type` | skb timestamp type (`0 = UNSPEC`, `1 = DELIVERY_MONO`) | tc_action, tc, tcx, netkit |
| `hwtstamp` | skb hardware timestamp | tc_action, tc, tcx, netkit, cgroup_skb |
| `data` | Packet data pointer | xdp, flow_dissector, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `data_meta` | Packet metadata pointer | xdp, tc_action, tc, tcx, netkit |
| `data_end` | Packet end pointer | xdp, flow_dissector, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `ingress_ifindex` | Ingress interface index | xdp, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_lookup, sk_skb, sk_skb_parser |
| `sample` / `raw` | Raw lirc mode2 sample word | lirc_mode2 |
| `value` | Low 24-bit lirc mode2 payload value | lirc_mode2 |
| `mode` | High-byte lirc mode2 event kind mask | lirc_mode2 |
| `access_type` | Encoded cgroup device access type | cgroup_device |
| `device_access` | cgroup device access flags (`access_type >> 16`) | cgroup_device |
| `device_type` | cgroup device kind (`access_type & 0xffff`) | cgroup_device |
| `major` | Requested device major number | cgroup_device |
| `minor` | Requested device minor number | cgroup_device |
| `ifindex` | Interface index (`xdp_md.ingress_ifindex` on XDP, `__sk_buff.ifindex` on skb-backed packet programs) | xdp, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `tc_index` | skb tc_index | socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `hash` | skb hash, or sk_reuseport selection hash on sk_reuseport | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_reuseport, sk_skb, sk_skb_parser |
| `hash_recalc` / `recalc_hash` | skb hash from `bpf_get_hash_recalc`, recomputing it if needed | lwt_*, tc_action, tc, tcx, netkit, sk_skb, sk_skb_parser |
| `socket_cookie` | Stable kernel socket cookie, or `0` when an skb has no known socket | socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_reuseport, sk_skb, sk_skb_parser, sock_ops |
| `socket_uid` | Owner UID of the socket associated with the current skb | socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `netns_cookie` | Stable kernel network-namespace cookie | socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, sock_ops |
| `rx_queue_index` | XDP receive queue index | xdp |
| `egress_ifindex` | XDP egress interface index | xdp:devmap |
| `user_family` | Userspace-requested socket family | cgroup_sock_addr |
| `user_ip4` | IPv4 destination/source address in host byte order | cgroup_sock_addr (*4 hooks) |
| `user_ip6` | IPv6 address as four host-order `u32` words | cgroup_sock_addr (*6 hooks) |
| `user_port` | Requested port in host byte order | cgroup_sock_addr (*4/*6 hooks) |
| `family` | Kernel socket family | cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `sock_type` | Socket type | cgroup_sock, cgroup_sock_addr |
| `protocol` / `ip_protocol` | Socket protocol on socket contexts; skb protocol / ethertype on skb-backed packet contexts; IP protocol on sk_reuseport | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_reuseport, sk_skb, sk_skb_parser |
| `bound_dev_if` | Bound device ifindex | cgroup_sock (sock_create, sock_release) |
| `mark` | Socket or skb mark | cgroup_sock (sock_create, sock_release), socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb |
| `priority` | Socket or skb priority | cgroup_sock (sock_create, sock_release), socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `state` | Current socket or TCP state | cgroup_sock, sock_ops |
| `op` | sock_ops callback opcode | sock_ops |
| `args` | sock_ops callback argument words as four host-order `u32` values | sock_ops |
| `reply` | sock_ops reply word, overlapping the first callback argument word | sock_ops |
| `replylong` | sock_ops reply words as four host-order `u32` values, overlapping `args` | sock_ops |
| `is_fullsock` | Whether the context has a full socket | sock_ops |
| `snd_cwnd` | Current sending congestion window | sock_ops |
| `srtt_us` | Smoothed RTT in microseconds shifted by 3 | sock_ops |
| `cb_flags` | Requested sock_ops callback flags | sock_ops |
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
| `skb_len` | Total packet length on packet-aware callbacks after proving a packet-aware `ctx.op` branch | sock_ops |
| `skb_tcp_flags` | Packet TCP flags on packet-aware callbacks after proving a packet-aware `ctx.op` branch | sock_ops |
| `skb_hwtstamp` | Packet hardware timestamp after proving a timestamp `ctx.op` branch (`16`-`20`) | sock_ops |
| `msg_src_ip4` | IPv4 source address in host byte order | cgroup_sock_addr (sendmsg4) |
| `msg_src_ip6` | IPv6 source address as four host-order `u32` words | cgroup_sock_addr (sendmsg6) |
| `remote_ip4` | Remote IPv4 address in host byte order | cgroup_sock, cgroup_sock_addr (connect4, getpeername4, sendmsg4, recvmsg4), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `remote_ip6` | Remote IPv6 address as four host-order `u32` words | cgroup_sock, cgroup_sock_addr (connect6, getpeername6, sendmsg6, recvmsg6), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `remote_port` | Remote port in host byte order | cgroup_sock, cgroup_sock_addr (connect4, connect6, getpeername4, getpeername6, sendmsg4, sendmsg6, recvmsg4, recvmsg6), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_ip4` | Local IPv4 address in host byte order | cgroup_sock (post_bind4), cgroup_sock_addr (bind4, getsockname4, sendmsg4), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_ip6` | Local IPv6 address as four host-order `u32` words | cgroup_sock (post_bind6), cgroup_sock_addr (bind6, getsockname6, sendmsg6), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `local_port` | Local port in host byte order | cgroup_sock (post_bind4, post_bind6), cgroup_sock_addr (bind4/bind6, getsockname4/getsockname6), cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `rx_queue_mapping` | Socket receive-queue mapping (`-1` if unset) | cgroup_sock |
| `sk` / `sock` / `socket` | Typed `bpf_sock *` pointer for socket projection such as `$ctx.sk.family`, `$ctx.sock.family`, or `$ctx.sk.bound_dev_if`; currently exposes `bound_dev_if`, `family`, `type`, `protocol`, `mark`, `priority`, `src_ip4` / `local_ip4`, `src_ip6` / `local_ip6`, `src_port` / `local_port`, `dst_port` / `remote_port` (raw network byte order), `dst_ip4` / `remote_ip4`, `dst_ip6` / `remote_ip6`, `state`, `rx_queue_mapping`, plus `cgroup_id` and `ancestor_cgroup_id.N` (`cgroup_skb` only). On program types where the corresponding helpers are valid, `$ctx.sk.tcp.<field>` / `$ctx.sock.tcp.<field>` expose null-safe TCP metrics from `struct bpf_tcp_sock`, while `$ctx.sk.full.<field>`, `$ctx.socket.full.<field>`, and `$ctx.sk.listener.<field>` expose fields from `bpf_sk_fullsock` / `bpf_get_listener_sock`; direct chained fields and bound helper-pointer field reads return `0` when there is no socket or the helper returns null. The helper-returned pointer can also be used for truthiness, for example `let tcp = $ctx.sk.tcp; if $tcp { $tcp.snd_cwnd }` or `let listener = $ctx.sock.listener; if $listener { $listener.family }`. On iterator programs, `sock` / `socket` keep the iterator-root meaning rather than the generic `bpf_sock` context pointer. | socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `flow_keys` | Typed `bpf_flow_keys *` pointer for flow-dissector projection and scalar assignment such as `$ctx.flow_keys.nhoff`, `$ctx.flow_keys.ip_proto`, `$ctx.flow_keys.ipv6_dst.3`, or `mut ctx = $ctx; $ctx.flow_keys.ip_proto = 6` | flow_dissector |
| `nf_state` | Typed `nf_hook_state *` pointer for netfilter projection such as `$ctx.nf_state.hook`, `$ctx.nf_state.pf`, `$ctx.nf_state.in.ifindex`, or `$ctx.nf_state.out.ifindex`; `ctx.state` is also accepted as a netfilter-specific alias | netfilter |
| `skb` | Typed `sk_buff *` pointer for netfilter projection such as `$ctx.skb.len` | netfilter |
| `hook` | Netfilter hook number from `nf_hook_state.hook` | netfilter |
| `pf` / `protocol_family` | Netfilter protocol family from `nf_hook_state.pf` | netfilter |
| `bind_inany` | sk_reuseport bind-in-any state | sk_reuseport |
| `migrating_sk` | Typed nullable migrating `bpf_sock *` pointer on sk_reuseport (`null` during ordinary select, populated during migration) | sk_reuseport |
| `task` / `current_task` | Current `task_struct *` from `bpf_get_current_task_btf`; BTF-backed fields such as `$ctx.task.pid` can be projected directly or after binding the pointer to a local when kernel BTF is available. `$ctx.task.pt_regs.arg0` through `.arg5` and `$ctx.task.pt_regs.retval` expose `bpf_task_pt_regs` register slots through the same architecture-aware pt_regs offset model used by kprobe args. On tracepoints, use `$ctx.current_task` when you need the builtin rather than a payload field named `task`. | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, lsm_cgroup |
| `cgroup` / `current_cgroup` | Current task default `cgroup *`; lowers through trusted BTF field loads for `$ctx.task.cgroups.dfl_cgrp` when kernel BTF is available, so it can be used as the owner pointer for `--kind cgrp-storage` without spelling task internals or losing verifier pointer provenance. BTF-backed cgroup fields can also be projected directly or after binding the pointer to a local, for example `$ctx.current_cgroup.kn.id` or `let cg = $ctx.current_cgroup; $cg.kn.id` on kernels that expose that layout. On tracepoints, use `current_cgroup` when you need the builtin rather than a payload field named `cgroup`. | kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, lsm_cgroup |
| `cookie` | Socket lookup cookie | sk_lookup |
| `level` | Socket-option level | cgroup_sockopt |
| `optname` | Socket-option name | cgroup_sockopt |
| `optlen` | Socket-option length | cgroup_sockopt |
| `optval` | Kernel pointer to the sockopt buffer | cgroup_sockopt |
| `optval_end` | Kernel pointer to the end of the sockopt buffer | cgroup_sockopt |
| `sockopt_retval` (`ctx.retval` on cgroup_sockopt) | Getsockopt return value on `get` hooks | cgroup_sockopt |
| `arg0`-`argN` | Function arguments or raw sampled ABI register slots; kernel-BTF-backed contexts also expose named `ctx.arg.<name>` aliases when kernel BTF includes names | kprobe, kprobe.multi, ksyscall, uprobe, uprobe.multi, fentry, fexit, fmod_ret, tp_btf, lsm, lsm_cgroup, struct_ops, raw_tracepoint, raw_tracepoint.w, perf_event |
| `arg_count` | Number of argument registers available to a BTF-backed tracing program (`bpf_get_func_arg_cnt`) | fentry, fexit, fmod_ret, tp_btf, lsm |
| `retval` | Return value | kretprobe, kretprobe.multi, kretsyscall, uretprobe, uretprobe.multi, fexit, fmod_ret |

Tracepoint fields are read from `/sys/kernel/tracing/events/<category>/<name>/format`.

`ctx.sk.tcp` currently exposes `snd_cwnd`, `srtt_us`, `rtt_min`,
`snd_ssthresh`, `rcv_nxt`, `snd_nxt`, `snd_una`, `mss_cache`,
`ecn_flags`, `rate_delivered`, `rate_interval_us`, `packets_out`,
`retrans_out`, `total_retrans`, `segs_in`, `data_segs_in`, `segs_out`,
`data_segs_out`, `lost_out`, `sacked_out`, `bytes_received`,
`bytes_acked`, `dsack_dups`, `delivered`, `delivered_ce`, and
`icsk_retransmits`.

## Program-Family Notes

The compiler tracks compatibility requirements at both the program-family and
parsed-target level. Live-attach rejection messages include these feature
requirements, for example base program families, kernel BTF, BPF trampolines,
TCX, netfilter links and defrag targets, route LWT, struct_ops family targets
such as `tcp_congestion_ops`, `hid_bpf_ops`, `sched_ext_ops`, and `Qdisc_ops`,
XDP attach modes, devmap/cpumap secondary sections, and multi-buffer sections,
cgroup v2, cgroup program families, and cgroup UNIX socket-address hooks. Live-load preflight also
reports source-verified map-kind, global data-section, typed map-value field,
modeled helper, compiler-generated bytecode feature, source-preserved
known-kfunc, and source-preserved context-field requirements from the compiled
object, and too-old-kernel diagnostics include the source URL for the effective
minimum-kernel floor. Compiled-feature metadata currently covers BPF-to-BPF subprogram calls
and bounded backward-branch loops. Compiled program/object metadata also
exposes aggregate `compatibility_minimum_kernel` and
`compatibility_minimum_kernel_source` fields across those source-verified
categories, an aggregate program/attach
`compatibility_default_test_lane`, and `compatibility_maximum_kernel_exclusive`
plus `compatibility_maximum_kernel_exclusive_source` when bounded
source-verified features are present. Known kfunc compatibility windows can
carry maximum-exclusive kernel bounds and sources for source-verified
transitional kfunc spellings. Context
fields that lower through modeled
helpers inherit those helper minimum-kernel/source records, and source-verified
direct UAPI fields carry context-field floors where their introduction point is
known. These labels describe feature surfaces.
`ebpf spec` reports each requirement with a feature category, a default test
lane (`host-safe`, `host-gated`, `dry-run`, or `vm-only`), a lane description,
and nullable minimum-kernel/source fields. These lanes are test-planning
metadata, not live-attach authorization flags; use the separate
`live_attach_*` fields to inspect loader policy. Those fields include a
machine-readable `live_attach_status` (`default-allowed`, `requires-opt-in`,
or `unsupported`), nullable `live_attach_unsupported_reason` metadata for
compile/dry-run-only targets, and nullable `live_attach_opt_in_reason`
metadata for risky but implemented families such as unclassified struct_ops,
sched_ext, hid_bpf_ops, and Qdisc_ops. `live_attach_default_test_lane` combines
feature compatibility with current loader policy, so unsupported live targets
report `dry-run` even when their kernel feature lane would otherwise be
host-gated or VM-only. `external_alpha_status` compresses those live-loader
and test-lane facts into the consumption labels used by external-alpha docs:
`live-supported`, `host-gated`, `dry-run-only`, `vm-only`, or
`unsafe-opt-in`. Kernel-BTF-backed target families also
expose `kernel_target_validation` and
`kernel_target_validation_help`, so tooling can present target-signature,
tracepoint, or LSM-hook guidance before attach. Source-verified requirements
carry minimum
versions, `compatibility_minimum_kernel` reports the maximum known requirement
for the parsed target, `compatibility_minimum_kernel_source` reports one source
for that aggregate floor, and `compatibility_default_test_lane` reports the most
restrictive default lane across those requirements. The `intrinsics` list is program- and
attach-aware, and first-class helper-backed commands expose aggregate
compatibility metadata plus `backing_helpers` records with source-checked
helper minimum-kernel metadata. Intrinsics that imply a context-field ABI
dependency expose `context_field_requirements`, such as `assign-socket`
reporting `ctx:sk` for supported tc and sk_lookup targets, and the intrinsic
row's aggregate compatibility floor combines that target-specific ABI floor
with the always-required backing helper floor.
Mode- or kind-sensitive intrinsic rows also expose `variants` records that map
the accepted flag/kind to the exact helper floor and, for map-family choices,
the map-kind compatibility floor for the parsed target.
The `kfunc_calls` list reports modeled kfunc-call surfaces whose availability
is constrained by the parsed program or callback, such as XDP metadata kfuncs
or sched_ext callback kfuncs, including modeled arity, argument kinds, return
kind, pointer-space/size rules, and source-checked kfunc compatibility metadata
when available.
Individual context-field, context-projection, and context-write records also
carry nullable `compatibility_minimum_kernel` and
`compatibility_minimum_kernel_source` fields that aggregate the known direct
context ABI, write-only surface, and backing helper/kfunc floors for that row.
The component `minimum_kernel`, `backing_helper_minimum_kernel`,
`helper_minimum_kernel`, and `kfunc_minimum_kernel` fields remain present where
they apply. Packet-capable program records also expose a `packet_headers` list
with the packet header view names, aliases, protocol-following views, payload
step support, fields, byte offsets, endian normalization, and bitfield slices
available through `$ctx.data` projections.
When a feature is unmodeled or kernel-version-specific, the kernel verifier and
loader remain authoritative.

Kernel-BTF-backed attach specs accept both the normal and sleepable
section spellings where Aya/libbpf do: `fentry:func` / `fentry.s:func`,
`fexit:func` / `fexit.s:func`, `lsm:hook` / `lsm.s:hook`, and
`lsm_cgroup:hook`. The
sleepable forms preserve the `.s` section prefix in dry-run ELF output
and loader attach.

User-probe specs also accept sleepable section spellings:
`uprobe.s:/path/to/bin:function` and `uretprobe.s:/path/to/bin:function`.
They preserve the `.s` section prefix in dry-run ELF output and use the
same pt_regs argument/return-value context surface as ordinary uprobes.
`uprobe.multi:/path/to/bin:pattern`, `uretprobe.multi:/path/to/bin:pattern`,
and their `.s` forms emit libbpf-style multi-uprobe wildcard sections;
live attach resolves the wildcard against the target ELF's function symbols
and creates bounded ordinary uprobe/uretprobe links for each match.

`freplace:FUNCTION` (aliases `extension:FUNCTION` and `ext:FUNCTION`)
emits a `freplace/FUNCTION` extension section for replacing a global
function in another loaded BPF program. This is compile/dry-run only for
now: live loading requires a target program FD and BTF-compatible target
function at load time, so the current model intentionally exposes no
target-function argument context.

`syscall:LABEL` emits a `syscall` section for `BPF_PROG_TYPE_SYSCALL`.
Local kernel headers describe this as a program type that can execute
syscalls through dedicated helpers. Because that is a high-risk surface,
the current model is compile/dry-run only and exposes no context. The
only modeled helper surface is explicit `helper-call` access to the
syscall-program helpers `bpf_sys_bpf`, `bpf_btf_find_by_name_kind`,
`bpf_sys_close`, and `bpf_kallsyms_lookup_name`; other raw helpers are
rejected on `syscall:*` until they have an explicit policy.

`iter:TARGET` currently has compile/dry-run support for BPF iterator
sections such as `iter:task`, emitting `iter/task`. All iterator targets
expose iterator metadata through `$ctx.meta` / `$ctx.iter_meta`.
Task-bearing iterators (`iter:task`, `iter:task_file`, and `iter:task_vma`)
also expose the nullable iterated task through `$ctx.task` / `$ctx.iter_task`.
`iter:task_file` exposes `$ctx.fd` / `$ctx.iter_fd` and `$ctx.file` /
`$ctx.iter_file`, `iter:task_vma` exposes `$ctx.vma` / `$ctx.iter_vma`, and
`iter:cgroup` exposes `$ctx.cgroup` / `$ctx.iter_cgroup`. BPF object
iterators expose their natural roots too: `$ctx.map` on `iter:bpf_map`,
`iter:bpf_map_elem`, `iter:bpf_sk_storage_map`, and `iter:sockmap`;
`$ctx.key` / `$ctx.value` on map-element iterators where those payload slots
exist; `$ctx.prog` on `iter:bpf_prog`; and `$ctx.link` on `iter:bpf_link`.
Network iterators expose `$ctx.sk_common` plus `$ctx.uid` on `iter:tcp`,
`$ctx.udp_sk` / `$ctx.uid` / `$ctx.bucket` on `iter:udp`, and
`$ctx.unix_sk` / `$ctx.uid` on `iter:unix`; these socket roots are BTF-backed
when kernel BTF is available.
Socket map iterators expose `$ctx.sk` / `$ctx.iter_sock` for their `sock *`
payload. Other simple single-pointer iterator contexts expose their
kernel-native roots: `$ctx.dmabuf`, `$ctx.rt`, `$ctx.kmem_cache`, `$ctx.ksym`,
and `$ctx.netlink_sk` for `iter:dmabuf`, `iter:ipv6_route`,
`iter:kmem_cache`, `iter:ksym`, and `iter:netlink`, respectively.
BTF-backed iterator roots can be bound to locals before projection, for example
`let meta = $ctx.iter_meta; $meta.seq_num` or
`if $ctx.iter_task { $ctx.iter_task.pid | count }`.
`$ctx.current_task` and `$ctx.current_cgroup` remain reserved for helper-backed
current-task semantics on task-aware tracing families. Iterator seq-file output
helpers are modeled for explicit escape-hatch use: `helper-call "bpf_seq_write"
SEQ DATA LEN`, `helper-call "bpf_seq_printf" SEQ FMT FMT_SIZE DATA DATA_LEN`,
and `helper-call "bpf_seq_printf_btf" SEQ BTF_PTR 16 FLAGS` are iter-only,
require a kernel `seq_file *` argument, and require stack/map-backed buffers.
`FMT_SIZE` must fit `1..=u32::MAX`, and `LEN` must fit `0..=u32::MAX`; `DATA_LEN` must be a multiple of
8 capped to `MAX_BPRINTF_VARARGS * 8` (`96` bytes). `bpf_seq_write` may use
`0` for `DATA` only when `LEN` is also `0`, and `bpf_seq_printf` may use
`0` for `DATA` only when `DATA_LEN` is also `0`.
Live attach is rejected until the loader grows BPF iterator link/seq-file
support.

`xdp`, `tc_action`, `tc`, `tcx`, `netkit`, and `cgroup_skb` expose `ctx.cpu`, `ctx.ktime`,
`ctx.packet_len`, `ctx.ingress_ifindex`, `ctx.ifindex`, and raw
packet pointers `ctx.data` / `ctx.data_end`. `sk_msg`, `sk_skb`, and
`sk_skb_parser` also expose `ctx.data` / `ctx.data_end` on their
message or skb contexts. `socket_filter` keeps `ctx.cpu`,
`ctx.ktime`, `ctx.packet_len`, `ctx.ingress_ifindex`, and `ctx.ifindex`,
but it does not expose raw packet pointers. Scalar packet byte reads
work through normal Nushell indexing such as `($ctx.data | get 0)`,
and fixed-width big-endian scalars can be read directly through cell
paths such as `$ctx.data.u16be.6` or `$ctx.data.u32be.0`. These lower
to data_end-guarded packet loads. On `xdp`, `lwt_xmit`,
`tc_action`, `tc`, `tcx`, `netkit`, `sk_msg`, `sk_skb`, and `sk_skb_parser`, the same
scalar/header packet paths are also writable through ordinary
cell-path updates
after shadowing the immutable closure parameter as mutable, for
example `mut ctx = $ctx; $ctx.data.0 = 0xff`, `mut ctx = $ctx;
$ctx.data.u16be.6 = 0x86dd`, or `mut ctx = $ctx;
$ctx.data.eth.ethertype = 0x86dd`; bound packet-pointer aliases such as
`mut data = $ctx.data; $data.0 = 0xff`, pipeline `get` roots such as
`mut data = ($ctx | get data); $data.0 = 0xff`, record-held aliases such as
`mut rec = { data: $ctx.data }; $rec.data.0 = 0xff`, and record pipelines such as
`mut rec = ({ ok: true } | upsert data ($ctx | get data)); $rec.data.0 = 0xff` use the same
guarded write path. Those lower to guarded packet
stores and automatically normalize big-endian packet scalars back to
network byte order. Other packet families remain read-only for direct
packet writes. Fixed header views `eth`, `arp`, `ipv4`, `ipv6`, `icmp`,
`icmpv6`, `udp`, and `tcp` are also available, for example
`$ctx.data.eth.ethertype`, `$ctx.data.eth.arp.opcode`,
`$ctx.data.eth.payload.ipv4.protocol`,
`$ctx.data.eth.payload.ipv6.next_header`,
`$ctx.data.eth.payload.ipv4.payload.icmp.type`, or
`$ctx.data.eth.payload.ipv6.payload.icmpv6.code`. Nested
protocol-following views reuse the same runtime packet stepping as
explicit `.payload`, so forms like `$ctx.data.eth.ipv4.tcp.seq` and
`$ctx.data.eth.ipv6.udp.src` also skip stacked VLAN tags, runtime-sized
IPv4 headers, and the bounded common IPv6 extension-header chain
automatically. ARP exposes fixed Ethernet/IPv4 fields such as
`hardware_type`, `protocol_type`, `opcode`, `sender_mac`, `sender_ip`,
`target_mac`, and `target_ip`. IPv4 exposes derived `version`, `ihl`, `dscp`,
`ecn`, `flags`, `reserved_flag`, `dont_fragment`, `more_fragments`, and
`fragment_offset` fields; IPv6 exposes derived `version`, `traffic_class`, and
`flow_label` fields; TCP exposes derived `data_offset`, `reserved`,
`flags`, and per-flag `ns`, `cwr`, `ece`, `urg`, `ack`, `psh`, `rst`,
`syn`, and `fin` fields; ICMP and ICMPv6 expose the raw
`rest_of_header` word plus echo `echo_id` and `echo_sequence` fields.
Packet headers also accept common kernel-header field aliases such as
`eth.h_proto`, `ipv4.tot_len`, `ipv4.saddr`, `udp.source`, `udp.dest`,
`tcp.source`, and `tcp.dest`. Those header views also support `payload`
stepping:
`$ctx.data.eth.payload` skips Ethernet and up to two stacked VLAN tags
when present, `$ctx.data.eth.payload.ipv4.payload` skips a runtime-sized
IPv4 header using the IHL nibble, `$ctx.data.eth.payload.ipv6.payload`
skips the fixed 40-byte IPv6 header plus a bounded chain of common
IPv6 extension headers (`hop-by-hop`, `routing`, `fragment`, `auth`,
and `destination options`), `$ctx.data.eth.payload.ipv4.payload.icmp.payload`
and `$ctx.data.eth.payload.ipv6.payload.icmpv6.payload` skip the fixed
8-byte ICMP header, and `$ctx.data.eth.payload.ipv4.payload.tcp.payload`
skips a runtime-sized TCP header using the data offset. `xdp`
additionally exposes `ctx.data_meta`, `ctx.ifindex`, and
`ctx.rx_queue_index`; `ctx.ifindex` and `ctx.rx_queue_index` require
the Linux 4.16 `xdp_md` metadata fields. `xdp:devmap` secondary
programs additionally expose `ctx.egress_ifindex`, which requires the
Linux 5.8 `xdp_md` egress metadata field and the devmap expected attach
type.
`ctx.data_meta` is a
packet-metadata pointer: scalar reads such as `($ctx.data_meta | get 0)`
use the same packet address space as `ctx.data`, but they are guarded
against `ctx.data` rather than `ctx.data_end`; writable aliases can also
come from pipeline `get`, for example `mut meta = ($ctx | get data_meta); $meta.0 = 7`. `tc_action`, `tc`, `tcx`, and `netkit` also expose
`ctx.data_meta` with the same `ctx.data`-guarded packet semantics,
which is useful for consuming metadata carried forward from earlier
packet-processing stages. `tc_action:LABEL` and its `action:LABEL`
alias emit an `action` section with TC-style return aliases and the
same skb packet/context fields. Its helper surface mirrors the
kernel TC cls_act helper family for first-class packet redirects,
skb relayout/edit helpers, cgroup-array membership, and helper-backed
skb metadata fields; live attach is intentionally rejected until the
loader grows an explicit tc-action attach path.
`tcx:IFACE:ingress|egress` emits `tcx/ingress` or `tcx/egress` sections
using the same SCHED_CLS skb context family as TC and live-attaches
through a TCX BPF link on kernels that support TCX. Return aliases are
`"next"` for `-1`, `"pass"` / `"ok"` for `0`, `"drop"` for `2`, and
`"redirect"` for `7`.
`netkit:IFACE:primary|peer` emits `netkit/primary` or `netkit/peer`
sections using the same SCHED_CLS skb context family. It is compile/dry-run
only for now; live attach is rejected until the loader has an explicit
Netkit attach path. Return aliases match TCX: `"next"` for `-1`,
`"pass"` / `"ok"` for `0`, `"drop"` for `2`, and `"redirect"` for `7`.
`adjust-packet --head|--meta|--tail DELTA`
is the preferred first-class XDP relayout surface; it lowers to
`bpf_xdp_adjust_head`, `bpf_xdp_adjust_meta`, or `bpf_xdp_adjust_tail`
and materializes the XDP context pointer automatically. On `tc_action`, `tc`,
`tcx`, `netkit`, `sk_skb`, and `sk_skb_parser`, `adjust-packet --head|--tail DELTA`,
`adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]`
are the preferred first-class skb relayout surfaces; `lwt_*` programs
also support the `--pull` form. These lower to `bpf_skb_change_head`,
`bpf_skb_change_tail`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room`
with the ambient skb context pointer materialized automatically. Raw
`bpf_skb_change_head` calls require `head_room` to be `0..i32::MAX`
and flags to be `0`; raw `bpf_skb_change_tail` calls require `new_len`
to be `0..i32::MAX` and flags to be `0`. Raw `bpf_skb_pull_data` calls
require `len` to be `0` through `u32::MAX`. The kernel still enforces its
configuration-dependent `BPF_SKB_MAX_LEN` ceiling at runtime. After XDP adjust helpers, previously
loaded packet pointers are invalid and must be reloaded from
`ctx.data`, `ctx.data_meta`, and `ctx.data_end` before further packet
access. After skb relayout helpers, reload `ctx.data` and
`ctx.data_end` before further packet access. The raw
`helper-call "bpf_xdp_adjust_*" $ctx DELTA` and `helper-call "bpf_skb_*" ...`
forms are still modeled when you need the escape hatch. `lwt_xmit`,
`tc_action`, `tc`, `tcx`, `netkit`, `sk_skb`, and `sk_skb_parser` also model the shared skb
packet-edit helpers through the ordinary helper surface, including
`bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`,
`bpf_clone_redirect`, `bpf_get_hash_recalc`, `bpf_csum_update`,
`bpf_csum_level`, and `bpf_set_hash_invalid`. `tc_action`, `tc`, `tcx`, `netkit`,
`sk_skb`, and `sk_skb_parser` additionally model `bpf_skb_vlan_push`,
`bpf_skb_vlan_pop`, `bpf_skb_adjust_room`, and `bpf_set_hash`. Raw
`bpf_clone_redirect` calls require `ifindex` to be `0` through `u32::MAX`;
raw `bpf_skb_store_bytes` calls require positive `len` in `1..=u32::MAX`;
raw `bpf_skb_vlan_push` calls require `vlan_proto` and `vlan_tci` to be
`0` through `u16::MAX`; raw `bpf_set_hash` calls require `hash` to be
`0` through `u32::MAX`; raw `bpf_csum_update` calls require `csum` to be
`0` through `u32::MAX`.
`bpf_skb_store_bytes` flags may contain only `BPF_F_RECOMPUTE_CSUM` and
`BPF_F_INVALIDATE_HASH`; `bpf_l3_csum_replace` flags may contain only
`BPF_F_HDR_FIELD_MASK`, and `bpf_l4_csum_replace` flags may contain only
`BPF_F_MARK_MANGLED_0`, `BPF_F_MARK_ENFORCE`, `BPF_F_PSEUDO_HDR`,
`BPF_F_HDR_FIELD_MASK`, and `BPF_F_IPV6`. For both checksum replacement
helpers, the offset must be even and fit `0..0xffff`, and the masked
header-field size must be `0`, `2`, or `4`. When that masked
header-field size is `0`, `from` must also be `0`.
Raw `bpf_csum_level` calls require the `level` selector to be
`BPF_CSUM_LEVEL_QUERY`, `BPF_CSUM_LEVEL_INC`, `BPF_CSUM_LEVEL_DEC`, or
`BPF_CSUM_LEVEL_RESET`.
`bpf_skb_adjust_room` `len_diff` must be between `-0xfff` and `0xfff`,
mode must be `BPF_ADJ_ROOM_NET` or `BPF_ADJ_ROOM_MAC`, and generic skb
adjust-room flags may contain only the modeled `BPF_F_ADJ_ROOM_*` bits,
including the high-byte `BPF_F_ADJ_ROOM_ENCAP_L2(len)` field. The
compiler also rejects statically known combinations that set both L3
encap flags, both L4 encap flags, or both L3 decap flags. On `sk_skb`
and `sk_skb_parser`, the kernel's stream-skb adjust-room variant requires
`MODE = 0` and `FLAGS = 0`.
These skb mutation helpers invalidate guarded
direct packet-pointer facts when the kernel helper contract says the
underlying packet buffer may change. Raw packet-copy helpers are modeled too:
`bpf_skb_load_bytes` works on `flow_dissector`, `socket_filter`, `lwt_*`,
`tc`, `tcx`, `netkit`, `cgroup_skb`, `sk_reuseport`, `sk_skb`, and `sk_skb_parser`;
`bpf_skb_load_bytes` / `bpf_skb_store_bytes` offsets must fit `0..i32::MAX`,
and load/store lengths must be positive and fit `1..=u32::MAX` while still
satisfying the buffer-size rule.
In `flow_dissector`, `bpf_skb_load_bytes` offsets must fit `0..0xffff`.
`bpf_skb_load_bytes_relative` works on `socket_filter`, `tc`, `tcx`, `netkit`, `cgroup_skb`,
and `sk_reuseport`, with `offset` limited to `0..0xffff`, positive `len`
capped to `u32::MAX`, and `start_header` limited to `BPF_HDR_START_MAC` or
`BPF_HDR_START_NET`; and
`bpf_xdp_get_buff_len`, `bpf_xdp_load_bytes`, and `bpf_xdp_store_bytes` are
XDP-only. XDP byte helper offsets must fit `0..0xffff`, and lengths must fit
`1..=0xffff`. XDP
targets default to SKB/generic attach mode for safer development attaches;
that explicit attach-mode flag requires Linux 4.12. Driver mode also
requires Linux 4.12, and hardware offload mode requires Linux 4.13. Use
`xdp:IFACE:drv` or `xdp:IFACE:hw`
when driver or hardware mode is intentional. Append
`:frags`, for example `xdp:IFACE:drv:frags`, when the program needs the
kernel `xdp.frags` section for multi-buffer packets. `xdp:devmap` and
`xdp:cpumap` emit the secondary-program `xdp/devmap` and `xdp/cpumap`
sections with the ordinary XDP context/return surface; they are
compile/dry-run only until the loader models map-entry program loading.
`ctx.egress_ifindex` follows the kernel verifier rule and is only available
on `xdp:devmap` secondary programs; ordinary interface XDP and `xdp:cpumap`
programs still expose ingress ifindex and RX queue metadata. XDP, TC, TCX, Netkit, and LWT also
model `bpf_csum_diff`; its `from_size` and `to_size` arguments must be
multiples of four and fit `0..u32::MAX`, its `seed` must fit
`0..u32::MAX`, and a null `from` or `to` buffer is accepted only when
the paired size is zero. `ctx.xdp_buff_len` exposes
`bpf_xdp_get_buff_len` directly for XDP programs that need total
multi-buffer packet size rather than the linear `ctx.packet_len`. XDP,
tc_action, TC, TCX, and Netkit also model `helper-call "bpf_check_mtu" $ctx IFINDEX MTU_LEN_PTR LEN_DIFF FLAGS`;
`IFINDEX` must fit `u32`, `MTU_LEN_PTR` must be a stack/map-backed `u32`
pointer, `LEN_DIFF` must fit `s32`, and XDP requires `FLAGS = 0`. TC/TCX
flags may contain only `BPF_MTU_CHK_SEGS` (`0x01`); when that segment-check
flag is set, `LEN_DIFF` must be `0` and statically known nonzero stack
values stored at `MTU_LEN_PTR` are rejected. Dynamic or map-backed runtime
values at `MTU_LEN_PTR` remain kernel-enforced for segment checks. XDP,
tc_action, TC, TCX, and Netkit also
model `helper-call "bpf_fib_lookup" $ctx PARAMS_PTR PLEN FLAGS`, where
`PARAMS_PTR` must be a stack/map-backed `bpf_fib_lookup` buffer whose
accessible size covers `PLEN`, and `PLEN` must fit `64..=i32::MAX` to
cover the modeled `struct bpf_fib_lookup` size. `FLAGS` may contain only modeled
`BPF_FIB_LOOKUP_*` bits (`0x3f`); the compiler also requires
`BPF_FIB_LOOKUP_TBID` to be paired with `BPF_FIB_LOOKUP_DIRECT` and rejects
`BPF_FIB_LOOKUP_MARK` with `BPF_FIB_LOOKUP_DIRECT`. `tc_action`, TC, TCX, Netkit, and `lwt_xmit` model
the skb tunnel metadata helpers:
`helper-call "bpf_skb_get_tunnel_key" $ctx KEY_PTR SIZE FLAGS`,
`helper-call "bpf_skb_set_tunnel_key" $ctx KEY_PTR SIZE FLAGS`,
`helper-call "bpf_skb_get_tunnel_opt" $ctx OPT_PTR SIZE`, and
`helper-call "bpf_skb_set_tunnel_opt" $ctx OPT_PTR SIZE`. `KEY_PTR` and
`OPT_PTR` must be stack/map-backed buffers whose accessible size covers
`SIZE`. For tunnel-option helpers, `SIZE` must be positive and
`bpf_skb_get_tunnel_opt` sizes fit `u32`; `bpf_skb_set_tunnel_opt` sizes must
fit `1..=255` and be a multiple of 4. For tunnel-key helpers, `SIZE` must be a
known constant and one
of the modeled kernel-compatible `struct bpf_tunnel_key` prefix sizes
(`8`, `22`, `24`, `28`, or `44` bytes). `bpf_skb_get_tunnel_key` accepts only
`BPF_F_TUNINFO_IPV6` and `BPF_F_TUNINFO_FLAGS`, while
`bpf_skb_set_tunnel_key` accepts only the kernel's tunnel-key flag bits
through `0x1f`. Runtime tunnel address-family compatibility remains
kernel-enforced. `tc_action`, TC, TCX, and Netkit also model
`helper-call "bpf_skb_get_xfrm_state" $ctx INDEX XFRM_STATE_PTR SIZE 0`;
`XFRM_STATE_PTR` must be a stack/map-backed output buffer whose
accessible size covers `SIZE`; `INDEX` must fit `u32`, `SIZE` must be
`sizeof(struct bpf_xfrm_state)` (`28`), and the final reserved flags argument
must be zero.
`tc_action`, Netkit, TC egress, and TCX egress expose skb cgroup/classifier
metadata as ordinary `ctx.cgroup_classid` and `ctx.route_realm` fields; TC action
and TC/TCX egress also expose `ctx.skb_cgroup_id`. LWT programs expose `ctx.cgroup_classid` and
`ctx.route_realm` through the same helper surface. `ctx.skb_ancestor_cgroup_id.N` exposes the
parameterized skb ancestor cgroup helper with a constant numeric
ancestor level in `0..i32::MAX`. `ctx.csum_level` exposes the checksum-level query form
of `bpf_csum_level` on `lwt_xmit`, tc_action, TC, TCX, Netkit, `sk_skb`, and `sk_skb_parser`
programs; inc/dec/reset remain helper-call operations because they mutate skb metadata.
`ctx.hash_recalc` exposes `bpf_get_hash_recalc` on LWT and the same
tc_action/TC/TCX/Netkit/`sk_skb` surface when a valid skb hash is needed after packet edits. The
skb-backed packet contexts
(`socket_filter`, `tc_action`, `tc`, `tcx`, `netkit`, `cgroup_skb`, `sk_skb`, and `sk_skb_parser`)
also expose `ctx.sk` / `ctx.sock` / `ctx.socket` for typed `bpf_sock`
projection such as `$ctx.sk.family`, `$ctx.sock.src_port`,
`$ctx.socket.dst_port`, or `$ctx.sk.mark`; the `local_ip4` / `local_ip6` / `local_port` and
`remote_ip4` / `remote_ip6` / `remote_port` aliases are accepted for
the corresponding kernel `src_*` / `dst_*` socket members. `cgroup_skb`
also exposes `$ctx.sk.cgroup_id`, `$ctx.sock.cgroup_id`, and
`$ctx.socket.ancestor_cgroup_id.N` through the socket cgroup helpers,
returning `0` when no socket is present. Common skb metadata includes `ctx.pkt_type`,
`ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`,
`ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.napi_id`,
`ctx.gso_segs`, `ctx.gso_size`, `ctx.tc_index`, and `ctx.hash`.
Additional metadata is family-specific: `ctx.tc_classid`,
`ctx.wire_len`, and `ctx.tstamp_type` are available on tc_action,
tc, tcx, and netkit; `ctx.tstamp` and `ctx.hwtstamp` are available on tc_action, tc, tcx, netkit,
and cgroup_skb; `ctx.mark` is available on cgroup_sock `sock_create` /
`sock_release`, socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb;
and `ctx.priority` is available on cgroup_sock `sock_create` /
`sock_release` and across the skb-backed packet families. `cgroup_skb`,
`sk_skb`, and `sk_skb_parser` also
expose direct socket-common and tuple aliases (`ctx.family`,
`ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`,
`ctx.local_ip6`, `ctx.local_port`) from the ambient `__sk_buff`
context; the IPv4 address and remote-port fields are normalized to
host byte order, and the IPv6 fields stay fixed arrays of four
host-order `u32` words. `ctx.eth_protocol` and `ctx.vlan_proto` are
normalized to host byte order, and `ctx.cb` follows the same
fixed-array model as `ctx.args`. Writable skb
metadata is attach-sensitive. On `socket_filter`, fixed `ctx.cb.N`
is writable. On `lwt_*`, `ctx.mark`, `ctx.priority`, and fixed
`ctx.cb.N` are writable. On `tc_action`, `tc`, `tcx`, and `netkit`, `ctx.mark`,
`ctx.queue_mapping`, `ctx.priority`, `ctx.tc_index`,
`ctx.tc_classid`, fixed `ctx.cb.N`, and `ctx.tstamp` are writable.
On `cgroup_skb`, `ctx.mark`, `ctx.priority`, and fixed `ctx.cb.N`
are writable on both directions, and `ctx.tstamp` is additionally
writable on `:egress`. On `sk_skb` and `sk_skb_parser`,
`ctx.priority` and `ctx.tc_index` are writable. These all use
ordinary assignment after shadowing the closure parameter as mutable,
for example `mut ctx = $ctx; $ctx.mark = 7`, `mut ctx = $ctx;
$ctx.cb.0 = 1`, `mut ctx = $ctx; $ctx.priority = 3`, `mut ctx = $ctx;
$ctx.tc_index = 5`, or `mut ctx = $ctx; $ctx.tstamp = 123`. Bound
full-context aliases and record-held full-context aliases use the same
write path, so forms like `mut event = $ctx; $event.tstamp = 123` and
`mut rec = { event: $ctx }; $rec.event.tstamp = 123` are equivalent
when the underlying field is writable on that program family. Other
skb-backed metadata fields remain read-only on the remaining hooks.
When the timestamp type must also change, `tc_action`, `tc`, `tcx`, and `netkit` model
`helper-call "bpf_skb_set_tstamp" $ctx TSTAMP TSTAMP_TYPE`; the
current kernel UAPI uses `0` for `BPF_SKB_TSTAMP_UNSPEC` and `1` for
`BPF_SKB_TSTAMP_DELIVERY_MONO`, and the compiler rejects other values.
`tc_action`, TC, TCX, Netkit, and `cgroup_skb` also
model `helper-call "bpf_skb_ecn_set_ce" $ctx` for setting IPv4/IPv6 ECN
CE when the packet is ECN-capable. `tc_action`, TC, TCX, and Netkit model
`helper-call "bpf_skb_change_proto" $ctx PROTO 0` and
`helper-call "bpf_skb_change_type" $ctx TYPE`; change-type calls accept
only `PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_MULTICAST`, or
`PACKET_OTHERHOST` (`0..3`), and change-proto calls accept only `ETH_P_IP`
or `ETH_P_IPV6`. Protocol changes can resize the skb, so packet pointers
must be reloaded and re-guarded afterward.
The initial `socket_filter` surface
uses targets like `socket_filter:udp4:127.0.0.1:31337`,
`socket_filter:udp6:[::1]:31337`, `socket_filter:tcp4:127.0.0.1:31337`,
and `socket_filter:tcp6:[::1]:31337`, which create and keep open a
bound socket while attached. `socket_filter` return values are
snapshot lengths: return `0` to drop the packet or a positive value to
keep it, and aliases like `"pass"` / `"keep"` expand to
`ctx.packet_len`. Deeper TCP option parsing, ICMP subtype-specific body
decoding, ESP/non-front-decodable IPv6 extension headers, and named
packet-program action helpers are still not modeled, but compile-time
action aliases are available in return position. XDP closures can return strings like
`"pass"` / `"drop"`, TC / tc_action closures can return strings like `"ok"` /
`"shot"`, and TCX/Netkit closures can return strings like `"next"` / `"pass"` /
`"ok"` / `"drop"` / `"redirect"`. Raw numeric return codes still work. `redirect IFINDEX` is
the preferred first-class surface for `bpf_redirect` on XDP, tc, tcx, and netkit,
and `redirect --flags N IFINDEX` exposes the helper flags argument
directly; redirect ifindexes must be `0` through `u32::MAX`, and XDP still requires `FLAGS = 0`. On `tc_action`, `tc:...:ingress`, `tcx:...:ingress`, and netkit,
`redirect --peer IFINDEX` is the preferred first-class surface for
`bpf_redirect_peer` and still requires `FLAGS = 0`. On tc_action/tc/tcx/netkit,
`redirect --neigh IFINDEX` is the preferred first-class surface for
the default-neighbor form of `bpf_redirect_neigh`, lowering to
`bpf_redirect_neigh(IFINDEX, 0, 0, FLAGS)`; `FLAGS` must also stay
`0`. The raw `helper-call "bpf_redirect*" ...` forms enforce the same
ifindex bounds and remain modeled when you need the escape hatch. For
raw `bpf_redirect_neigh`, a non-null params buffer is bounded by `PLEN`,
and `PLEN` must fit `0..=i32::MAX`.

On XDP, `adjust-packet --head|--meta|--tail DELTA` is the preferred first-class surface for packet relayout. It selects the corresponding `bpf_xdp_adjust_*` helper, materializes the ambient context pointer automatically, and returns the helper result directly; XDP adjust `DELTA` must fit signed 32-bit range (`i32::MIN..=i32::MAX`). On `tc_action`, `tc`, `tcx`, `netkit`, `sk_skb`, and `sk_skb_parser`, `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` do the same for `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room`; pull `LEN` must be `0` through `u32::MAX`, and LWT programs also support `adjust-packet --pull LEN`.

XDP RX metadata kfuncs stay explicit because they return errno values and write through output pointers rather than behaving like ordinary infallible context fields. Use `kfunc-call "bpf_xdp_metadata_rx_timestamp" $ctx TIMESTAMP_BUF`, `kfunc-call "bpf_xdp_metadata_rx_hash" $ctx HASH_BUF RSS_TYPE_BUF`, or `kfunc-call "bpf_xdp_metadata_rx_vlan_tag" $ctx VLAN_PROTO_BUF VLAN_TCI_BUF` on XDP programs with stack/map buffers of 8, 4/4, and 2/2 bytes respectively. The compiler rejects these kfuncs outside XDP and preserves source-backed kernel floors for compatibility reporting.

XDP XFRM state lookup is also modeled as an explicit kfunc escape hatch: `kfunc-call "bpf_xdp_get_xfrm_state" $ctx OPTS OPTS_SIZE` requires `OPTS` to be a stack/map buffer whose bounded size covers `OPTS_SIZE`, and `OPTS_SIZE` must be positive. A non-null returned `xfrm_state` reference must be released on every path with `kfunc-call "bpf_xdp_xfrm_state_release" $state`; the compiler rejects leaks and rejects these kfuncs outside XDP.

On XDP, tc_action, tc, tcx, and netkit, `redirect IFINDEX` is the preferred first-class surface for packet redirection. `redirect --peer IFINDEX` selects `bpf_redirect_peer` on tc_action, `tc:...:ingress`, `tcx:...:ingress`, or netkit, and `redirect --neigh IFINDEX` selects the default-neighbor form of `bpf_redirect_neigh` on tc_action/tc/tcx/netkit. All three forms require `IFINDEX` to be `0` through `u32::MAX` and return the helper result directly so a closure can end with `redirect ...`.

On XDP, `redirect-map MAP KEY --kind devmap|devmap-hash|cpumap|xskmap` is the preferred first-class surface for `bpf_redirect_map`. It returns the helper result directly, so a closure can end with `redirect-map ...` instead of spelling the helper name through `helper-call`. Its `--flags` value is limited to the two fallback return-code bits plus `BPF_F_BROADCAST` and `BPF_F_EXCLUDE_INGRESS`.

On `sk_msg`, `sk_skb`, and `sk_skb_parser`, `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class surface for the socket redirect helpers. It picks `bpf_msg_redirect_{map,hash}` or `bpf_sk_redirect_{map,hash}` from the current program type, materializes the ambient context pointer automatically, and returns the helper result directly so a closure can end with `redirect-socket ...`. Sockmap redirect helper keys must fit `0..=u32::MAX`; sockhash variants materialize `KEY` as a map-key pointer. On `sk_reuseport`, `redirect-socket MAP KEY --kind reuseport-sockarray` selects `bpf_sk_select_reuseport`, materializes the `u32` key pointer required by the helper, and requires `--flags 0`.

On `tc_action`, `tc:...:ingress`, `tcx:...:ingress`, and `sk_lookup`, ordinary assignment to `ctx.sk` / `ctx.sock` / `ctx.socket` is the preferred zero-flag surface for `bpf_sk_assign`: `mut ctx = $ctx; $ctx.sock = $sk`, or `$ctx.socket = 0` on `sk_lookup` to clear a previous selection. `assign-socket SK [--flags FLAGS]` remains available when the program needs the helper status or explicit flags. `tc_action` and TC/TCX ingress require zero flags. `sk_lookup` accepts `--replace` and `--no-reuseport` for `BPF_SK_LOOKUP_F_REPLACE` and `BPF_SK_LOOKUP_F_NO_REUSEPORT`.

On `sock_ops`, `$ctx | map-put MAP KEY --kind sockmap|sockhash` is the preferred first-class surface for `bpf_sock_{map,hash}_update`. The pipeline input is the current `sock_ops` context, `KEY` is materialized as the map key pointer, and `--flags` is limited to `BPF_ANY`, `BPF_NOEXIST`, or `BPF_EXIST`.

Local-storage maps use the ordinary map surface: `$ctx.sk | map-get sock_state --kind sk-storage`, `$ctx.task | map-get task_state --kind task-storage --init { hits: 0 }`, `$ctx.cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 }`, `$ctx.arg0.f_inode | map-delete inode_state --kind inode-storage`, `$ctx.current_task | map-contains task_state --kind task-storage`, and `$ctx.current_cgroup | map-contains cgrp_state --kind cgrp-storage` lower to the corresponding `bpf_*_storage_{get,delete}` helpers. `--init VALUE` passes a typed initial value and defaults `--flags` to `1` (`BPF_LOCAL_STORAGE_GET_F_CREATE`); omit it for lookup-only behavior. Storage-get flags are limited to `0` or `BPF_LOCAL_STORAGE_GET_F_CREATE`. `map-contains` performs a lookup-only storage get and compares the returned pointer against null. The raw storage helper spelling still works through `helper-call` for low-level debugging, but `map-get` / `map-contains` / `map-delete` are the preferred resource-oriented forms. The legacy cgroup-attached `bpf_get_local_storage` helper is recognized in the typed raw-helper model with `flags = 0`, but its deprecated cgroup-storage map family is still not materialized; use `--kind cgrp-storage` with the ordinary map surface for new programs.

Tail calls are exposed as ordinary control flow with `tail-call MAP INDEX` or `INDEX | tail-call MAP`. `MAP` is emitted as a BPF `prog_array`, and `INDEX` must fit `0..=u32::MAX`; successful tail calls do not return to the current program, while the compiler emits a default `0` return for the kernel miss/limit fallback path. The raw `helper-call "bpf_tail_call"` form remains available for low-level debugging and enforces the same index range, but `tail-call` is the preferred surface because it lowers through the modeled terminator path. Because the tail-called program may mutate packet data, the local verifier follows the kernel and requires packet pointers loaded before a raw `bpf_tail_call` helper call to be reloaded before later packet access on the fallback path.

`perf_event` currently supports software `cpu-clock`, `task-clock`, `context-switches`, `cpu-migrations`, `page-faults`, `minor-faults`, and `major-faults`, plus hardware `cpu-cycles`, `instructions`, `cache-references`, `cache-misses`, `branch-instructions`, `branch-misses`, `bus-cycles`, `stalled-cycles-frontend`, `stalled-cycles-backend`, and `ref-cpu-cycles` through specs like `perf_event:software:cpu-clock` or `perf_event:hardware:cpu-cycles`. Optional selectors `cpu=N`, `pid=N`, `period=N`, and `freq=N` are supported; omitting the sample policy defaults to `period=1000000`, and omitting `cpu=` attaches on all online CPUs. `pid=N` scopes the event to a single process, and it can be combined with `cpu=N` for one-process/one-cpu sampling. The current surface uses ordinary helper-backed fields like `ctx.pid`, `ctx.comm`, `ctx.cpu`, and `ctx.ktime`, plus perf counter snapshots `ctx.perf_counter`, `ctx.perf_enabled`, and `ctx.perf_running` from `bpf_perf_prog_read_value`. It also reuses `ctx.arg0`-`ctx.arg5` as raw sampled pt_regs register slots, and on x86_64 builds it exposes the raw `bpf_perf_event_data` fields `ctx.sample_period` and `ctx.addr`. The `ctx.argN` values here are sampled register snapshots, not named BTF-backed function arguments.

`cgroup_sysctl` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.write`, `ctx.file_pos`, `ctx.sysctl_name` / `ctx.name`, `ctx.sysctl_base_name` / `ctx.base_name`, `ctx.sysctl_current_value` / `ctx.current_value`, and `ctx.sysctl_new_value` / `ctx.new_value`, and closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes. The sysctl name and value fields are stack-backed 256-byte buffers copied with `bpf_sysctl_get_name`, `bpf_sysctl_get_current_value`, or `bpf_sysctl_get_new_value`; use the raw helpers only when the program needs explicit return-code handling or a different buffer size. `ctx.file_pos` is writable through ordinary assignment after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.file_pos = 0`. Assigning a string or binary byte buffer to `ctx.sysctl_new_value` / `ctx.new_value`, for example `mut ctx = $ctx; $ctx.new_value = "1"`, lowers to `bpf_sysctl_set_new_value`; `ctx.write` remains read-only. Modeled sysctl helpers are available through the ordinary helper surface: `bpf_sysctl_get_name`, `bpf_sysctl_get_current_value`, `bpf_sysctl_get_new_value`, and `bpf_sysctl_set_new_value`. The kernel keeps their usual runtime semantics here: `bpf_sysctl_get_new_value` and `bpf_sysctl_set_new_value` return `-EINVAL` on read contexts, and `bpf_sysctl_get_name` flags are restricted to `0` or `BPF_F_SYSCTL_BASE_NAME`.

`cgroup_sock` currently supports `sock_create`, `sock_release`, `post_bind4`, and `post_bind6`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.family`, `ctx.sock_type`, `ctx.protocol` / `ctx.ip_protocol`, `ctx.state`, `ctx.rx_queue_mapping`, `ctx.socket_cookie`, `ctx.netns_cookie`, `ctx.remote_ip4`, `ctx.remote_ip6`, and `ctx.remote_port` on every supported hook. Direct `ctx.bound_dev_if`, `ctx.mark`, and `ctx.priority` are only available on `sock_create` / `sock_release`, matching the current upstream verifier surface more closely, and ordinary assignment is supported there after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.mark = 7`. Direct `ctx.local_ip4` is available on `post_bind4`, `ctx.local_ip6` on `post_bind6`, and `ctx.local_port` on both post-bind hooks. It also exposes typed `ctx.sk` / `ctx.sock` / `ctx.socket` pointers for ordinary socket projection such as `$ctx.sock.family`, `$ctx.socket.local_port`, `$ctx.sk.remote_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. On `cgroup_sock`, the source-side projection members follow the same attach-sensitive policy as the direct locals: `$ctx.sk.src_ip4` / `$ctx.sock.local_ip4` are only available on `post_bind4`, `$ctx.socket.src_ip6` / `$ctx.sk.local_ip6` on `post_bind6`, and `$ctx.sk.src_port` / `$ctx.sock.local_port` on both post-bind hooks. Destination-side projections such as `$ctx.socket.dst_port` / `$ctx.sk.remote_port` remain available on every hook.

`cgroup_device` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.access_type`, `ctx.device_access`, `ctx.device_type`, `ctx.major`, and `ctx.minor`, and closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes. `ctx.access_type` is the raw kernel encoding `(BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*`; `ctx.device_access` exposes the access flags and `ctx.device_type` exposes the block/char device kind.

`lirc_mode2` attaches to a lirc device path such as `/dev/lirc0`. It exposes `ctx.sample` / `ctx.raw` for the raw 32-bit mode2 sample word, `ctx.value` for the low 24-bit payload, and `ctx.mode` for the high-byte event kind mask. Raw LIRC helper calls are available on this program type: `bpf_rc_keydown` requires `protocol` and `toggle` to fit `0..=u32::MAX`, and `bpf_rc_pointer_rel` requires relative movement values to fit signed `s32`. It uses raw integer return codes; simple observation programs can return `0`.

`sock_ops` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes the sock_ops callback opcode and argument/reply union (`ctx.op`, `ctx.args`, `ctx.reply`, `ctx.replylong`), the socket tuple and metadata fields (`ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, `ctx.socket_cookie`, `ctx.netns_cookie`), the TCP/congestion and progress counters (`ctx.is_fullsock`, `ctx.snd_cwnd`, `ctx.srtt_us`, `ctx.cb_flags`, `ctx.state`, `ctx.rtt_min`, `ctx.snd_ssthresh`, `ctx.rcv_nxt`, `ctx.snd_nxt`, `ctx.snd_una`, `ctx.mss_cache`, `ctx.ecn_flags`, `ctx.rate_delivered`, `ctx.rate_interval_us`, `ctx.packets_out`, `ctx.retrans_out`, `ctx.total_retrans`, `ctx.segs_in`, `ctx.data_segs_in`, `ctx.segs_out`, `ctx.data_segs_out`, `ctx.lost_out`, `ctx.sacked_out`, `ctx.sk_txhash`, `ctx.bytes_received`, and `ctx.bytes_acked`), plus guarded packet-metadata fields `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.skb_len`, `ctx.skb_tcp_flags`, and `ctx.skb_hwtstamp`. It also exposes typed `ctx.sk` / `ctx.sock` / `ctx.socket` pointers for ordinary socket projection such as `$ctx.sock.family`, `$ctx.socket.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and remote port fields are normalized to host byte order. The IPv6 fields and `ctx.replylong` are exposed as fixed arrays of four host-order `u32` words, so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)` or `($ctx.replylong | get 0)`. `ctx.reply`, `ctx.replylong.<0-3>`, `ctx.cb_flags`, and `ctx.sk_txhash` are writable `u32` words and can be assigned with ordinary Nushell cell-path updates after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.reply = 1`, `mut ctx = $ctx; $ctx.replylong.0 = 7`, `mut ctx = $ctx; $ctx.cb_flags = 1`, or `mut ctx = $ctx; $ctx.sk_txhash = 7`. `ctx.cb_flags = ...` lowers through `bpf_sock_ops_cb_flags_set`; the other writable fields are direct context stores. Packet-aware callbacks use the same guarded packet-access model as XDP and tc, and the verifier now requires a proven packet-aware `ctx.op` branch before loading those packet fields; common packet-aware opcodes include active/passive established (`4` / `5`) and parse/write header option (`13` / `15`). `ctx.skb_tcp_flags` is also available on header-option length (`14`), while `ctx.skb_hwtstamp` requires timestamp callbacks (`16`-`20`). Modeled sock_ops helpers are also available through the ordinary helper surface, including `bpf_getsockopt`, `bpf_setsockopt`, `bpf_load_hdr_opt`, `bpf_store_hdr_opt`, and `bpf_reserve_hdr_opt`; socket-option `optlen` values must fit `1..=i32::MAX`, and header-option helper lengths must fit `2..=u32::MAX`. The verifier models the kernel callback/flag rules for header-option helpers: unflagged `bpf_load_hdr_opt` requires a packet-data `ctx.op`, `bpf_store_hdr_opt` requires `ctx.op == 15`, `bpf_reserve_hdr_opt` requires `ctx.op == 14`, and `bpf_load_hdr_opt` with `BPF_LOAD_HDR_OPT_TCP_SYN` skips the packet-data proof. The sock_ops kfunc escape hatch is intentionally narrow; currently `kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0` is modeled for timestamp-sendmsg callbacks, with callback and flag details still enforced by the kernel. sock_ops uses raw integer return codes; observation-only examples should return `1`.

For TCP header-option helpers, the modeled length range is `2..=u32::MAX`; `len = 1` is rejected before lowering.

`cgroup_sockopt` currently attaches to `get` and `set` cgroup socket-option hooks such as `/sys/fs/cgroup:get` or `/sys/fs/cgroup:set`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.level`, `ctx.optname`, `ctx.optlen`, `ctx.optval`, `ctx.optval_end`, `ctx.netns_cookie`, and `ctx.sockopt_retval` / `ctx.retval` on `get` hooks, plus typed `ctx.sk` / `ctx.sock` / `ctx.socket` pointers for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sock.src_port`, `$ctx.socket.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. `optval` / `optval_end` are surfaced as kernel pointers, so ordinary pointer reads like `($ctx.optval | get 0)` can inspect the buffer; `read-kernel-str` remains limited to probe/tracing-style program families by the current program capability policy. Ordinary assignment now also covers the writable scalar surfaces the kernel exposes here: `ctx.sockopt_retval` / `ctx.retval` on `cgroup_sockopt:get`, `ctx.level` / `ctx.optname` on `cgroup_sockopt:set`, `ctx.optlen` on either hook, and fixed-index sockopt-buffer rewrites such as `mut ctx = $ctx; $ctx.optval.0 = 1`, `mut optval = $ctx.optval; $optval.0 = 1`, `mut optval = ($ctx | get optval); $optval.0 = 1`, `def get_optval [event] { $event | get optval }; mut optval = (get_optval $ctx); $optval.0 = 1`, or `mut rec = { optval: $ctx.optval }; $rec.optval.0 = 1`. Modeled socket-option helpers are also available through the ordinary helper surface here, including `bpf_getsockopt` and `bpf_setsockopt` on the current sockopt context; their `optlen` values must fit `1..=i32::MAX`. Closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes.

`cgroup_sock_addr` currently exposes `ctx.cpu`, `ctx.ktime`,
`ctx.socket_cookie`, `ctx.netns_cookie`, `ctx.user_family`,
`ctx.family`, `ctx.sock_type`, and `ctx.protocol` / `ctx.ip_protocol`
on every modeled hook. IPv4/IPv6 hooks additionally expose
`ctx.user_ip4`, `ctx.user_ip6`, and `ctx.user_port`, plus
`ctx.msg_src_ip4` on `sendmsg4` and `ctx.msg_src_ip6` on `sendmsg6`.
It also normalizes the attach-sensitive IPv4/IPv6 hooks onto the
ordinary tuple surface where the kernel semantics are clear:
`connect4` / `connect6`, `getpeername4` / `getpeername6`,
`sendmsg4` / `sendmsg6`, and `recvmsg4` / `recvmsg6` expose
`ctx.remote_ip4`, `ctx.remote_ip6`, and `ctx.remote_port`; `bind4` /
`bind6` and `getsockname4` / `getsockname6` expose `ctx.local_ip4`,
`ctx.local_ip6`, and `ctx.local_port`; and `sendmsg4` / `sendmsg6`
additionally expose `ctx.local_ip4` / `ctx.local_ip6` over the
source-address fields. `sendmsg4` / `sendmsg6` still do not expose
`ctx.local_port`, because the kernel surface does not provide a
corresponding source-port field there. The `sendmsg*` local-IP aliases
inherit the `msg_src_ip*` compatibility floor because they write the
same physical kernel fields.

These mutable kernel fields can be assigned through the same aliases
after shadowing the closure parameter as mutable, for example
`mut ctx = $ctx; $ctx.remote_ip4 = 0x7f000001` on `connect4` /
`getpeername4` / `sendmsg4` / `recvmsg4`, `$ctx.local_port = 8080`
on `bind4` / `bind6` / `getsockname4` / `getsockname6`, or
`$ctx.local_ip6.0 = 0` on `bind6` / `getsockname6` / `sendmsg6`.
Bound and record-held full-context aliases follow the same writable
field policy, for example `mut event = $ctx; $event.remote_port = 8080`
or `mut rec = { event: $ctx }; $rec.event.remote_port = 8080` on hooks
where `remote_port` is writable.

The UNIX hooks `connect_unix`, `sendmsg_unix`, `recvmsg_unix`,
`getpeername_unix`, and `getsockname_unix` emit the matching libbpf
`cgroup/*_unix` sections for compile/dry-run, but live attach is
rejected until Aya exposes the `BPF_CGROUP_UNIX_*` attach types or the
loader grows an equivalent lower-level attach path. Their direct read
surface is intentionally limited to common socket metadata, while path
mutation is available as ordinary assignment on UNIX hooks:
`mut ctx = $ctx; $ctx.sun_path = "/tmp/demo.sock"` lowers to
`bpf_sock_addr_set_sun_path`; bound or record-held aliases such as
`mut event = $ctx; $event.sun_path = "/tmp/demo.sock"` and
`mut rec = { event: $ctx }; $rec.event.sun_path = "/tmp/demo.sock"`
lower the same way. It also exposes typed `ctx.sk` / `ctx.sock` /
`ctx.socket` pointers for ordinary socket projection such as
`$ctx.sock.family`, `$ctx.socket.src_port`, `$ctx.sk.dst_port`,
`$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4
address and port fields are normalized to host byte order. The IPv6
fields are exposed as fixed arrays of four host-order `u32` words, so
ordinary Nushell indexing works, for example `($ctx.user_ip6 | get 3)`.
`cgroup_sock_addr` closures can return `"allow"` / `"deny"` instead of
raw `1` / `0` codes. Modeled socket helpers are also available through
the ordinary helper surface: `bpf_bind` on inet `connect4` / `connect6`
hooks, `bpf_getsockopt` / `bpf_setsockopt` across `cgroup_sock_addr`
hooks including UNIX hooks, and `bpf_sock_addr_set_sun_path` behind
`ctx.sun_path` assignment on UNIX hooks. `bpf_bind` `addr_len` and
socket-option `optlen` values must fit `1..=i32::MAX`. Numeric result codes still work too.

`sk_lookup` currently attaches to a network-namespace path such as `/proc/self/ns/net`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.family`, `ctx.protocol` / `ctx.ip_protocol`, `ctx.cookie`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, `ctx.ingress_ifindex`, and typed `ctx.sk` / `ctx.sock` / `ctx.socket` pointers for socket projection such as `$ctx.sk.bound_dev_if`, `$ctx.sock.src_port`, `$ctx.socket.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. `ctx.ingress_ifindex` has its own Linux 5.17 context-field floor, while the base `sk_lookup` tuple fields are Linux 5.9. `mut ctx = $ctx; $ctx.sk = $sk` selects a socket through `bpf_sk_assign` with zero flags, and assignments to `ctx.sk`, `ctx.sock`, or `ctx.socket` with `0` clear an earlier selection. `assign-socket $sk --replace` / `assign-socket 0 --replace` remain available when explicit sk_lookup flags are needed. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `sk_lookup` closures can return `"pass"` / `"drop"` instead of raw `1` / `0` result codes; `"allow"` / `"deny"` aliases also work.

`sk_reuseport` currently has compile/dry-run support for `sk_reuseport:select` and `sk_reuseport:migrate`. It emits `sk_reuseport` or `sk_reuseport/migrate` sections and exposes the `sk_reuseport_md` packet surface: `ctx.packet_len` / `ctx.len`, `ctx.data`, `ctx.data_end`, `ctx.eth_protocol`, `ctx.ip_protocol` / `ctx.protocol`, `ctx.hash`, `ctx.socket_cookie`, and `ctx.bind_inany`. It also exposes the selected `ctx.sk` / `ctx.sock` / `ctx.socket` socket pointer as non-null and the migrating `ctx.migrating_sk` / `ctx.migrating_socket` pointer as nullable for ordinary socket projections such as `$ctx.sock.bound_dev_if` or `$ctx.migrating_socket.state`; `ctx.migrating_sk` is null during ordinary selection and populated for migration programs. `redirect-socket MAP KEY --kind reuseport-sockarray` is the first-class socket-selection surface and lowers to `bpf_sk_select_reuseport`; its flags argument must be `0`. Live attach is intentionally rejected before Aya load until the loader has a safe reuseport attach implementation.

`raw_tracepoint.w` / `raw_tp.w` currently has compile/dry-run support for writable raw tracepoint targets such as `raw_tracepoint.w:sys_enter`. It emits a `raw_tracepoint.w/<name>` section and reuses the ordinary raw tracepoint positional argument surface (`ctx.arg0`, `ctx.arg1`, ...). Live attach is intentionally rejected before Aya load because the current loader does not preserve writable raw-tracepoint sections, and rewriting them as ordinary raw tracepoints would change verifier semantics.

`flow_dissector` currently has compile/dry-run support for network-namespace targets such as `flow_dissector:/proc/self/ns/net`. It emits a `flow_dissector` section and exposes the kernel's narrow `__sk_buff` flow-dissector surface: `ctx.data`, `ctx.data_end`, and `ctx.flow_keys` projections including `nhoff`, `thoff`, `addr_proto`, `is_frag`, `is_first_frag`, `is_encap`, `ip_proto`, `n_proto`, `sport`, `dport`, `ipv4_src`, `ipv4_dst`, fixed-array `ipv6_src` / `ipv6_dst` words, `flags`, and `flow_label`. Common aliases are also accepted for flow-key projections, such as `protocol` for `ip_proto`, `src_port` / `dst_port` for `sport` / `dport`, `src_ip4` / `dst_ip4` for IPv4 addresses, `src_ip6` / `dst_ip6` for IPv6 arrays, and `network_header_offset` / `transport_header_offset` for `nhoff` / `thoff`. Scalar `ctx.flow_keys` leaves are writable through ordinary assignment after shadowing the closure parameter or binding the pointer, for example `mut ctx = $ctx; $ctx.flow_keys.protocol = 6`, `mut keys = $ctx.flow_keys; $keys.dst_ip6.3 = 1`, or `mut keys = ($ctx | get flow_keys); $keys.dst_ip6.3 = 1`. User functions can return the same `get`-derived root before assignment, for example `def get_keys [event] { $event | get flow_keys }; mut keys = (get_keys $ctx); $keys.ip_proto = 17`. Length and protocol decisions should come from guarded packet reads or the dissected flow keys rather than direct `ctx.packet_len` / `ctx.protocol` fields. Return aliases are `"ok"` / `"parsed"` for `0`, `"drop"` for `2`, and `"continue"` / `"fallback"` for `129`. Live attach is intentionally rejected before Aya load because this loader does not yet implement safe flow-dissector attachment and Aya does not expose a high-level attach wrapper for this section.

`netfilter` currently has compile/dry-run support for targets such as `netfilter:ipv4:pre_routing[:priority=N][:defrag]`. It emits a `netfilter` section and exposes the safe scalar `bpf_nf_ctx.state` fields `ctx.hook` and `ctx.pf` / `ctx.protocol_family`, plus the verifier-provided trusted pointers `ctx.state` / `ctx.nf_state` (`nf_hook_state *`) and `ctx.skb` (`sk_buff *`) for ordinary typed projections such as `ctx.state.in.ifindex` or `ctx.skb.len`. Pointer-valued hops and scalar leaves from those trusted netfilter roots lower as direct trusted-BTF loads, preserving verifier provenance and avoiding probe-read helper calls. BPF-link specs accept `ipv4` / `ipv6` families and `pre_routing`, `local_in`, `forward`, `local_out`, or `post_routing` hooks; `defrag` requires priority greater than `-400` and Linux 6.6+. Return aliases are `"drop"` / `"deny"` for `0`, `"accept"` / `"allow"` / `"pass"` / `"ok"` for `1`, `"stolen"` for `2`, `"queue"` for `3`, and `"repeat"` for `4`. Live attach is intentionally rejected before Aya load until the loader has BPF-link netfilter attach support.

`lwt_in`, `lwt_out`, `lwt_xmit`, and `lwt_seg6local` currently have compile/dry-run support for descriptive targets such as `lwt_xmit:demo-route`. They emit their matching `lwt_*` sections and expose a conservative `__sk_buff` packet surface: `ctx.packet_len` / `ctx.len`, `ctx.data`, `ctx.data_end`, `ctx.eth_protocol` / `ctx.protocol`, `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.napi_id`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.ingress_ifindex`, `ctx.ifindex`, `ctx.hash`, `ctx.hash_recalc`, `ctx.cgroup_classid`, `ctx.route_realm`, `ctx.mark`, `ctx.priority`, and fixed `ctx.cb.N`. Kernel-rejected LWT skb fields such as `ctx.tc_classid`, `ctx.wire_len`, `ctx.tstamp`, `ctx.tstamp_type`, and `ctx.hwtstamp` are intentionally not exposed. `adjust-packet --pull LEN` is available across LWT programs for packet linearization. `lwt_in` and `lwt_xmit` model `helper-call "bpf_lwt_push_encap" $ctx TYPE HDR_PTR LEN`; the compiler rejects that helper outside `lwt_in` / `lwt_xmit`, `TYPE` must be `BPF_LWT_ENCAP_SEG6`, `BPF_LWT_ENCAP_SEG6_INLINE`, or `BPF_LWT_ENCAP_IP`, and `lwt_xmit` specifically requires `BPF_LWT_ENCAP_IP`. `HDR_PTR` must be a stack/map-backed header buffer whose accessible size covers `LEN`, and `LEN` must fit `1..=u32::MAX`. `lwt_xmit` additionally supports direct `ctx.data.*` packet stores, `redirect IFINDEX`, `adjust-packet --head|--tail DELTA`, `ctx.csum_level`, skb tunnel metadata helpers, and the modeled skb packet-edit helper surface also available to `tc_action` / tc / `sk_skb` (`bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_csum_update`, and `bpf_set_hash_invalid`). `lwt_seg6local` models `bpf_lwt_seg6_store_bytes`, `bpf_lwt_seg6_adjust_srh`, and `bpf_lwt_seg6_action`; those helpers are locally rejected outside `lwt_seg6local`, the Segment Routing offsets must fit `0..u32::MAX`, `bpf_lwt_seg6_adjust_srh` `DELTA` must fit signed `s32`, and the buffer-taking forms require stack/map-backed buffers sized by their `LEN` / `PARAM_LEN` arguments with positive sizes capped to `u32::MAX`. `bpf_lwt_seg6_action` requires `ACTION` to be `SEG6_LOCAL_ACTION_END_X`, `SEG6_LOCAL_ACTION_END_T`, `SEG6_LOCAL_ACTION_END_B6`, or `SEG6_LOCAL_ACTION_END_B6_ENCAP`; `SEG6_LOCAL_ACTION_END_X` requires `PARAM_LEN = 16`, and `SEG6_LOCAL_ACTION_END_T` requires `PARAM_LEN = 4`. `SEG6_LOCAL_ACTION_END_B6` and `SEG6_LOCAL_ACTION_END_B6_ENCAP` SRH layout validation remains kernel-enforced. All of these LWT mutating helpers can invalidate packet pointers, so reload and re-guard `ctx.data` / `ctx.data_end` afterward. Return aliases are `"ok"` / `"pass"` for `0`, `"drop"` for `2`, and `"redirect"` for `7`; `lwt_in` and `lwt_xmit` also accept `"reroute"` for `128`. Live attach is intentionally rejected before Aya load because this loader does not yet implement route LWT attachment and Aya does not parse these sections.

`sk_msg` currently attaches to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. Dry-run mode only requires a syntactically valid non-empty path; live attach validates that the pinned map exists. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.packet_len` / `ctx.len` / `ctx.size`, `ctx.data`, `ctx.data_end`, `ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`, plus typed `ctx.sk` / `ctx.sock` / `ctx.socket` pointers for socket projection such as `$ctx.sock.family`, `$ctx.socket.src_port`, `$ctx.sk.dst_port`, or `$ctx.sk.priority`. `ctx.data` / `ctx.data_end` use the same guarded packet access model as XDP and tc, so ordinary byte/scalar reads like `($ctx.data | get 0)` work, and direct scalar/header stores through `ctx.data.*` use the same guarded packet-store lowering as other writable packet contexts. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `sk_msg` uses raw integer verdict codes; closures can return `"pass"` / `"drop"` instead of raw `1` / `0`, and `"allow"` / `"deny"` aliases also work. `adjust-message --apply BYTES`, `adjust-message --cork BYTES`, `adjust-message --pull START END [--flags N]`, `adjust-message --push START LEN [--flags N]`, and `adjust-message --pop START LEN [--flags N]` are the preferred first-class message-byte surfaces here because they select the corresponding `bpf_msg_*` helper automatically from the current program type; byte counts, pull start/end, and push/pop start/len arguments must be `0` through `u32::MAX`, and pull/push/pop flags are reserved and must be `0`. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_msg_redirect_map` or `bpf_msg_redirect_hash` automatically from the current program type. Socket helper-backed projections are available through ordinary `ctx.sk.full.<field>`, `ctx.sock.listener.<field>`, and `ctx.socket.tcp.<field>` paths when the corresponding helper is valid.

`adjust-message --pull`, `adjust-message --push`, and `adjust-message --pop` can invalidate previously loaded `ctx.data` / `ctx.data_end` pointers, so reload them after the helper before reading packet bytes again. The message-data reshaping helpers reserve their flags arguments for future use, so `adjust-message --pull|--push|--pop ... --flags N` and raw `helper-call "bpf_msg_{pull,push,pop}_data" ...` require `N = 0`. `bpf_msg_pull_data` also rejects statically provable `END <= START` ranges; runtime message-length bounds remain kernel-enforced.

`sk_skb` currently emits `sk_skb/stream_verdict` programs attached to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. Dry-run mode only requires a syntactically valid non-empty path; live attach validates that the pinned map exists. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.napi_id`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.ingress_ifindex`, `ctx.ifindex`, `ctx.tc_index`, `ctx.hash`, `ctx.hash_recalc`, `ctx.csum_level`, `ctx.priority`, `ctx.socket_cookie`, `ctx.socket_uid`, `ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, and typed `ctx.sk` / `ctx.sock` / `ctx.socket` pointers through the existing skb-backed packet model, so ordinary guarded packet reads like `($ctx.data | get 0)` and socket projections like `$ctx.sock.family` work. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. This initial slice uses verdict-style return codes with `pass` / `drop` aliases. `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` are the preferred first-class skb relayout surfaces here because they select `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room` automatically from the current program type; the stream-skb adjust-room helper requires `--mode 0` and `--flags 0`. Modeled skb packet-edit helpers are also available through the ordinary helper surface, including `bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_get_hash_recalc`, `bpf_csum_update`, and `bpf_set_hash_invalid`. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_sk_redirect_map` or `bpf_sk_redirect_hash` automatically from the current program type. Reload `ctx.data` and `ctx.data_end` after `adjust-packet --head`, `adjust-packet --tail`, `adjust-packet --pull`, or `adjust-packet --room` before reading packet bytes again.

`sk_skb_parser` currently emits `sk_skb/stream_parser` programs attached to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. Dry-run mode only requires a syntactically valid non-empty path; live attach validates that the pinned map exists. It uses the same skb-backed packet context as `sk_skb`, including packet data, skb metadata, `ctx.hash_recalc`, `ctx.csum_level`, `ctx.socket_cookie`, `ctx.socket_uid`, tuple fields such as `ctx.family` / `ctx.remote_port` / `ctx.local_port`, and typed `ctx.sk` / `ctx.sock` / `ctx.socket` socket pointers, with the same host-order normalization rules for IPv4 addresses, remote ports, and IPv6 word arrays. Its return contract is a raw integer parser result rather than a verdict alias surface, so ordinary examples should return `0` or another integer length. `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` are the preferred first-class skb relayout surfaces here because they select `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room` automatically from the current program type; the stream-skb adjust-room helper requires `--mode 0` and `--flags 0`. Modeled skb packet-edit helpers are also available through the ordinary helper surface, including `bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_get_hash_recalc`, `bpf_csum_update`, and `bpf_set_hash_invalid`. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_sk_redirect_map` or `bpf_sk_redirect_hash` automatically from the current program type. Reload `ctx.data` and `ctx.data_end` after `adjust-packet --head`, `adjust-packet --tail`, `adjust-packet --pull`, or `adjust-packet --room` before reading packet bytes again.

`kprobe`, `kprobe.multi`, `ksyscall`, `uprobe`, and `uprobe.multi` expose `ctx.arg0`-`ctx.arg5` through `pt_regs`; `kretprobe`, `kretprobe.multi`, `kretsyscall`, `uretprobe`, and `uretprobe.multi` expose `ctx.retval` through `pt_regs`. `raw_tracepoint` and `raw_tracepoint.w` expose raw positional `ctx.argN` slots. `fentry`, `fexit`, `fmod_ret`, `tp_btf`, `lsm`, `lsm_cgroup`, and `struct_ops` callbacks resolve arguments from kernel BTF; those kernel-BTF-backed contexts also expose named aliases through `ctx.arg.<name>` when names are available, and `fexit` / `fmod_ret` additionally expose `ctx.retval`.
`kprobe.multi` emits `kprobe.multi/PATTERN` sections and `kretprobe.multi`
emits `kretprobe.multi/PATTERN` sections; live attach resolves the wildcard
against `/proc/kallsyms` and attaches ordinary kprobe/kretprobe links to each
match, rejecting overly broad patterns above the loader's safety cap.
`uprobe.multi` emits `uprobe.multi/PATH:PATTERN` sections and
`uretprobe.multi` emits `uretprobe.multi/PATH:PATTERN` sections; live attach
resolves the wildcard against the target ELF's function symbols and attaches
ordinary uprobe/uretprobe links to each match, also rejecting overly broad
patterns above the loader's safety cap. `ksyscall` emits `ksyscall/SYSCALL`
sections and `kretsyscall` emits `kretsyscall/SYSCALL` sections; live attach
resolves the syscall name against `/proc/kallsyms` and attaches to every
matching ABI wrapper on the host. `lsm_cgroup` emits `lsm_cgroup/HOOK`
sections and is compile/dry-run only until the loader can safely handle cgroup
LSM attachment. `uprobe.s` and `uretprobe.s` emit sleepable user-probe
sections with the same context surface as ordinary uprobes. `fmod_ret` emits
`fmod_ret/FUNC` or `fmod_ret.s/FUNC` sections and is compile/dry-run only until
the loader can safely handle modify-return attachment. Direct
`struct_ops:<value_type>.<callback>` targets expose callback metadata and
kernel-BTF context shape, but live registration happens through a
`struct_ops:<value_type>` object rather than by attaching the callback section
by itself.
Scalar and pointer trampoline values work directly. By-value trampoline args and pointer-backed trampoline args/returns can project scalar/pointer fields such as `ctx.arg0.some_field` and can cross intermediate and repeated pointer hops such as `ctx.arg0.foo.bar` or `ctx.arg0.fdt.fd.f_inode.i_ino`. Pointer-valued hops and scalar leaves from non-user function, LSM, and struct_ops BTF trampoline roots lower as direct trusted-BTF kernel loads, both inline and after binding the pointer to a local. `tp_btf` pointer arguments are different: the verifier exposes those argument values as scalars, so scalar projections from them stay null-guarded `bpf_probe_read_kernel` reads. User-space pointers continue to use user probe reads. Fixed-size arrays can also be indexed with numeric path segments like `ctx.arg0.comm.0`, and pointer-backed sequences can now also be indexed with constant numeric segments such as `ctx.arg0.fdt.fd.0.f_inode.i_ino` or `let fd = $ctx.arg0.fdt.fd; $fd.0.f_inode.i_ino`. The same typed pointer traversal also works through numeric `get`, for example `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`.
Stack-backed fixed arrays support the same runtime indexing, for example `let idx = ($ctx.pid mod 2); ($ctx.arg0.comm | get $idx)`. Bounded `for` loops over static integer ranges also lower to verifier-safe loops, so `for i in 0..0 { ... get $i ... }` now works, explicit negative-step descending ranges lower too, and bounded arithmetic on those indices such as `let j = (($i + 1) mod 2)` is preserved. The same range tracking now works for typed unsigned runtime fields such as `let idx = ($ctx.arg0.fdt.max_fds mod 2)`. Branch-sensitive narrowing also works for both bound and repeated direct paths, for example `let max = $ctx.arg0.fdt.max_fds; if $max > 0 { let idx = ($max - 1); ... }` or `if $ctx.arg0.fdt.max_fds > 0 { let idx = ($ctx.arg0.fdt.max_fds - 1); ... }`. Typed BTF bitfields can also be projected through the same paths, including after numeric `get`, for example `let idx = ($ctx.pid mod 2); let clamp = ($ctx.arg0.uclamp_req | get $idx); $clamp.value`.
Integer `match` range patterns support open and closed bounds, right-exclusive bounds, descending finite ranges that Nushell normalizes for membership, and explicit next-value stepped forms such as `0..2..10` or `0..2..`; zero-step explicit ranges are rejected before eBPF lowering.
Terminal array leaves and unsupported aggregate leaves are exposed as stack-backed byte buffers, while representable terminal struct leaves keep their field layouts, including BTF bitfield members, for `count` / `ebpf counters`, and single-value `emit` can stream those struct leaves as records. Nested array/record fields inside emitted values also decode recursively when the compiler can preserve their layouts. `emit` still preserves unsupported aggregate layouts as binary payloads, and `count` supports them as byte-buffer keys. `ebpf counters` decodes those keys using any schema the compiler still has: arrays and typed structs can surface as strings, lists, or records, while opaque aggregate layouts still display as `binary`.
Plain trampoline `ctx.argN` / `ctx.retval` loads also preserve their typed pointer or aggregate layouts across bindings, so `let files = $ctx.arg0; $files.fdt.fd.f_inode.i_ino`, `ctx.arg0.fdt.fd.0.f_inode.i_ino`, `let fd = $ctx.arg0.fdt.fd; $fd.0.f_inode.i_ino`, `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`, and `let inode = $ctx.arg0.f_inode; $inode.i_sb.s_flags` continue to type-check and lower as expected. Named parameter access works through the same typed lowering path, for example `ctx.arg.prev_cpu`, `ctx.arg.p.pid`, `ctx.arg.file.f_flags`, `ctx.arg.file.f_inode.i_ino`, or cgroup-LSM `ctx.arg.address.sa_family`. 16-byte byte-array/string keys such as `ctx.arg0.comm` continue to display as strings. Aggregate `fexit` / `fmod_ret` returns still depend on kernel trampoline support; some kernels reject struct returns entirely.

Generic named maps are also available through `map-define`, `map-get`, `map-put`, `map-delete`, `map-push`, `map-peek`, and `map-pop`. `map-define --key-type/--value-type` is a compile-time declaration for map layouts that cannot be inferred from a prior operation: `--key-type` fixes scalar or aggregate key size/materialization, while `--value-type` fixes value layout, especially verifier-managed fields such as `bpf_timer`, `bpf_spin_lock`, `bpf_wq`, `bpf_refcount`, `kptr:TYPE`, `bpf_list_head:TYPE:FIELD[:record{...}]`, and `bpf_rb_root:TYPE:FIELD[:record{...}]`; declared key/value layouts are also carried into object BTF as typed `key` / `value` map members. Source-level `record{...}` specs use natural field alignment and aligned array stride; padding is zero-filled by typed initializers and hidden from emitted BTF members. `kptr:TYPE` declares an 8-byte-aligned top-level map-value kptr slot for hash, array, or lru-hash maps and emits the kernel-visible `__kptr` BTF type tag for `TYPE`; projecting that field yields the map slot pointer needed by `helper-call "bpf_kptr_xchg"`. A declared `bpf_refcount` field is BTF-visible map-value metadata; `bpf_refcount_acquire_impl` expects the containing refcounted object pointer rather than the raw field pointer, so direct acquire from `$entry.refs` is intentionally rejected. Graph roots use `bpf_list_head:TYPE:FIELD[:record{...}]` or `bpf_rb_root:TYPE:FIELD[:record{...}]`, where `TYPE` is the contained object type and `FIELD` is its list/rbtree node field; with an optional payload record, the compiler emits a matching object struct whose first member is the node field and whose remaining payload fields can currently include fixed-layout scalar/aggregate fields plus `bpf_refcount`. The compiler also emits the required `contains:TYPE:FIELD` BTF declaration tag. Acquired graph object references returned from `bpf_list_pop_front`, `bpf_list_pop_back`, `bpf_rbtree_remove`, and `bpf_refcount_acquire_impl` carry that payload schema, so ordinary scalar payload projection such as `$obj.cookie` can be type-checked after a null check. Non-owning graph node results returned by `bpf_list_front`, `bpf_list_back`, `bpf_rbtree_first`, `bpf_rbtree_left`, and `bpf_rbtree_right` also carry the schema when they originate from a source-declared graph root with the compiler-emitted zero-offset node field; this enables payload projections such as `$node.cookie`, but it does not make the non-owning node an acquired reference. Graph-root kfuncs such as list push/pop/front/back and rbtree add/remove/first must run while a map-value `bpf_spin_lock` is held; the root and lock may be projected from different fields in the same map-value record, for example `record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}`. When both pointers carry map-value provenance, the local model requires the held lock to come from the same map lookup root as the graph root, a repeated lookup of the same map using the same key register, a copied scalar alias of that key, or a repeated lookup whose scalar keys are both proven to the same singleton constant; algebraically equivalent key expressions are not proven identical yet. Opaque verifier-managed field sizes are resolved from local kernel BTF when available because some UAPI shapes can grow across kernel releases; without kernel BTF, the compiler falls back to the first supported source-backed layouts. Bare graph root/node tokens such as `bpf_list_head`, `bpf_rb_root`, `bpf_list_node`, and `bpf_rb_node` are still rejected. `bpf_dynptr` and `bpf_dynptr_kern` are rejected as map-value fields because dynptr helpers model them as stack-only verifier state. `map-define --max-entries` sets a positive map capacity for value-carrying map families that expose `max_entries`, and declared maps now emit object map definitions even when no later map operation touches them. Pinned peers attached with the same `--pin` group reuse unambiguous capacity declarations too. For example, `map-define timers --kind array --key-type u32 --value-type 'record{timer:bpf_timer,cookie:u64}' --max-entries 1024` lets a later null-checked `map-get` project `$entry.timer` as a map-backed timer. `map-get`, `map-peek`, and `map-pop` return maybe-null pointers, and ordinary pointer truthiness is the preferred null check. When a prior typed `map-put` established the value layout in the same closure, projections like `let entry = ($ctx.pid | map-get seen_paths --kind hash); if $entry { $entry.dentry.d_flags }` lower through that preserved map-value schema, and whole-value uses like `{ $entry | emit }` or `{ $entry | count }` preserve the same typed aggregate layout instead of collapsing to a raw pointer scalar. Explicit comparisons such as `if $entry != 0` still work, but direct truthiness keeps source closer to ordinary Nushell control flow. That same typed `map-put` / `map-push` seeding now also accepts metadata-built record values when the record fields already have a truthful fixed layout and tracked semantics, so ordinary record construction can feed typed map flows without an intermediate local materialization step. The preserved layout also survives record construction, so `if $entry { { path: $entry } | emit }` streams `path` as a nested record instead of a raw pointer or opaque bytes. The same null-checked layout now also survives simple user-defined function boundaries, so `def project-entry [entry] { $entry }` can feed `if $entry { (project-entry $entry) | emit }` without collapsing back to an untyped scalar. Call-site typed arguments now also specialize simple user-defined functions, so callees can project typed fields directly from their parameters, for example `def inode-flags [file] { $file.f_inode.i_flags }`. Queue/stack maps now preserve their pushed value layouts the same way: a typed `map-push` establishes the layout used by later `map-peek` / `map-pop` in the same closure, and pinned peers attached with the same `--pin` group can reuse that schema too. Socket maps use `map-put` from `sock_ops` for updates and `redirect-socket` from `sk_msg` / `sk_skb` for redirects; reuseport socket arrays use `redirect-socket` from `sk_reuseport` for socket selection. Local-storage `map-get --init` uses the same typed value-schema path for `sk-storage`, `task-storage`, `inode-storage`, and `cgrp-storage` maps. Bloom-filter maps use the same typed `map-push` value layout path, but intentionally do not support first-class `map-peek` because kernel bloom-filter peek treats its value argument as an input membership probe rather than an output buffer. When looked-up aggregates are written back through `map-put`, the stored value shape stays canonical too, so map-to-map copies preserve the real aggregate layout instead of a pointer wrapper. When those maps are attached with the same `--pin` group, active pinned programs now reuse unambiguous typed key and value schemas across program boundaries too.

Leading annotated `mut` bindings at the top of an attached eBPF closure now lower as compiler-managed per-program globals backed by `.data` or `.bss`, so ordinary Nushell variable syntax can express private state without a helper: `{|ctx| mut state: int = 0; $state = ($state + 1); $state | count }`. The initializer must be a compile-time constant today, and may reference earlier leading immutable `let` declarations when those declarations also have supported compile-time constant initializers; only the leading declaration group at the top of the closure is hoisted this way. That is now the preferred small-state path when plain variable syntax is enough. For supported annotations, the declared Nushell type is now the layout source for that global, so record field order comes from the annotation rather than the record literal initializer. Annotated `record<...>` layouts use natural field alignment and aligned array stride, matching explicit `record{...}` specs. Non-`list<int>` typed list annotations use the initializer as a fixed-array length/layout exemplar, so scalar arrays such as `mut flags: list<bool> = [true false]` and record arrays such as `mut entries: list<record<pid: int cpu: int>> = [{pid: 7 cpu: 2} {pid: 9 cpu: 3}]` support ordinary cell-path projection and updates. When the annotation itself fully fixes a truthful layout, an empty record initializer works as a zero-initialized `.bss` initializer, for example `{|ctx| mut state: record<pid: int stats: record<hits: int ok: bool>> = {}; ... }`. Nested empty record fields can zero-fill nested scalar-record layouts while preserving explicit top-level fields, for example `{|ctx| mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 stats: {} }; ... }`. Current Nushell parsing still rejects `null` for typed mutable globals and rejects non-empty top-level typed-record initializers that omit declared fields, such as `{ pid: 7 }`, before the plugin can inspect the program. Use `{}` for all-zero scalar-record globals, provide all required top-level fields, or switch to `global-define --type` when the desired layout has no plain Nushell initializer. The zero-init path is intentionally limited to scalar and nested scalar-record layouts whose size is fixed by the plain Nushell annotation alone; string, binary, and list globals still need an explicit exemplar or the typed named-global path so the compiler knows their real capacity. Keep those annotated `mut` declarations before function definitions and other top-level statements; a typed `mut` that appears later is not treated as a compiler-managed global.

Compiler-managed named globals are still available through `global-define`, `global-get`, and `global-set` when you need an explicit shared name or source-order-independent declaration. Leading typed `mut` bindings remain the preferred private-state path when ordinary variable syntax is enough. These named globals are compiler-managed per-program globals backed by `.data` or `.bss`. `global-define` is declarative: by default a compile-time constant input establishes the fixed layout and initial contents without doing a runtime store, so source order does not matter. `global-define --zero` takes the next step and uses the input only for layout inference, allocating a zero-initialized `.bss` global without a runtime store. If you use `global-define --type`, no exemplar is needed for the layout: with no pipeline input it declares a zero-initialized global directly, and with a compile-time constant input it combines the explicit fixed layout with explicit initial contents. Currently `i8` / `i16` / `i32` / `int` (alias `i64`), `u8` / `u16` / `u32` / `u64`, `bool`, and `bytes:N` are supported as direct typed declarations, and that now also extends to `string:N`, `list:int:N` (alias `list:i64:N`), and fixed arrays such as `array{bool:4}`, `array{u32:4}`, `array{bytes:4:2}`, `array{string:8:2}`, `array{list:int:4:2}`, or `array{record{pid:int,cpu:u32}:2}`, plus nested `record{field:type,...}` declarations whose fields can themselves be scalars, fixed `bytes:N` / `binary:N`, `string:N`, `list:int:N`, `array{type:N}`, or further `record{...}` layouts. Source-level `record{...}` specs use natural field alignment and aligned array stride, so `record{pid:int,cpu:u32}` has four bytes of tail padding when embedded in an array. Typed initializers are zero-padded within those declared capacities, including record padding, and typed record initializers may omit fields that should start zeroed, so forms like `"bash" | global-define --type string:16 seen_comm`, `[true false] | global-define --type 'array{bool:4}' seen_flags`, `[11 22] | global-define --type 'array{u32:4}' seen_ports`, `[0x[01 02] 0x[03]] | global-define --type 'array{bytes:4:2}' seen_buffers`, `[[11 22] [33]] | global-define --type 'array{list:int:4:2}' seen_samples`, `[{pid: 7 cpu: 2} {pid: 9 cpu: 3}] | global-define --type 'array{record{pid:int,cpu:u32}:2}' seen_entries`, `{ entries: [{pid: 7 cpu: 2} {pid: 9 cpu: 3}] } | global-define --type 'record{entries:array{record{pid:int,cpu:u32}:2}}' seen_state`, `{ pid: 7, samples: [11 22] } | global-define --type 'record{pid:int,samples:list:int:4}' seen_state`, and `{ pid: 7 } | global-define --type 'record{pid:int,samples:list:int:4}' seen_state` are valid. Boolean constants do not implicitly initialize numeric type specs; use `bool` or `array{bool:N}` when the stored layout is boolean. `global-get` preserves those typed string/list/array field semantics too, so projections like `$state.msg`, `($state.vals | get 1)`, `($ports | get 0)`, `($entries | get 1).cpu`, or `($state.entries | get 1).cpu` behave the same way as the ordinary typed mutable global path. If you skip `global-define`, the first `global-set` for a given name still establishes the fixed layout used by later `global-get` and `global-set` calls in the same closure; when that first write is a compile-time constant the global is initialized from it, otherwise it starts zeroed. That same first-write inference now also works for metadata-built record values, including nested record builders, when every field already has a truthful fixed layout and tracked semantics, so ordinary record construction can seed named globals without an intermediate local materialization step. They are best suited for small per-program state without the overhead of an explicit map. Like the current mutable-capture path, they only support values with a truthful fixed layout.

An empty binary literal `0x[]` does not establish a fixed byte-buffer layout on its own. Use a non-empty binary initializer when you want layout inference, or provide an explicit `bytes:N` / `binary:N` type spec when a typed declaration should supply the zero-filled byte-buffer layout, including nested `record{...}` fields in `global-define --type`.

Generic map `--kind` now supports `hash`, `array`, `queue`, `stack`, `bloom-filter`, `cgroup-array`, `lpm-trie`, `lru-hash`, `per-cpu-hash`, `per-cpu-array`, and `lru-per-cpu-hash`. `queue` and `stack` use `map-push`, `map-peek`, and `map-pop` instead of `map-put` / `map-get`. Lookup-capable generic maps use `map-get` for pointer reads and `map-contains` for boolean membership checks; `map-contains` defaults to `--kind hash` and also accepts `array`, `lpm-trie`, `lru-hash`, `per-cpu-hash`, `per-cpu-array`, and `lru-per-cpu-hash`. `map-put` flags are limited to `BPF_ANY`, `BPF_NOEXIST`, or `BPF_EXIST`; queue/stack `map-push` flags are limited to `0` or `BPF_EXIST`. `bloom-filter` uses first-class `map-push` to insert values and `map-contains --kind bloom-filter` for membership probes. It does not support first-class `map-peek`, `map-pop`, `map-get`, `map-put`, or `map-delete`. Per-cpu maps use the ordinary `map-get` surface for current-CPU/default lookups; explicit CPU reads can use the modeled escape hatch `helper-call "bpf_map_lookup_percpu_elem" MAP KEY_PTR CPU --kind per-cpu-hash|per-cpu-array|lru-per-cpu-hash`, where `KEY_PTR` must already be a stack/map-backed key pointer and `CPU` must fit `0..=u32::MAX`. Socket map kinds (`sockmap` and `sockhash`) use `map-put` on `sock_ops` programs for updates and `redirect-socket` on message/SKB stream programs for redirects. `reuseport-sockarray` is reserved for `redirect-socket` on `sk_reuseport`, where it emits a `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` map and selects `bpf_sk_select_reuseport`. For map-name literals, later map operations can omit `--kind` when exactly one prior source-visible declaration, first-class map operation, or modeled raw helper map operand has already fixed that map name's kind; otherwise keep `--kind` explicit on ambiguous helper-only operands. Local-storage map kinds (`sk-storage`, `task-storage`, `inode-storage`, and `cgrp-storage`) use `map-get` / `map-contains` / `map-delete` over an owning object pointer instead of generic key/value update helpers. Special map families such as `ringbuf`, `user-ringbuf`, `perf-event-array`, `stack-trace`, and `prog-array` are selected by their owning surfaces (`emit`, modeled ringbuf/user-ringbuf helpers, perf-event output helpers, `ctx.kstack` / `ctx.ustack`, and `tail-call`) rather than generic map commands. The compiler also recognizes map families that need additional loader/modeling work: `array-of-maps` / `hash-of-maps` source-level `map-define --inner-map` declarations emit outer object map definitions and libbpf-compatible object BTF `values` metadata when the inner template is also emitted as a runtime map, and dry-run/object generation supports outer `map-get` / `map-contains` plus guarded dynamic inner `map-get`, `map-put`, `map-delete`, and `map-contains` through the returned pointer; live loading is still rejected before Aya because Aya 0.13 does not materialize `inner_map_fd` from that metadata. `arena` requires map-extra and mmap support; `struct-ops` belongs to struct_ops object loading; and deprecated cgroup-storage map types should use `cgrp-storage` instead. Raw ring-buffer helpers enforce the kernel flag contracts too: reserve flags must be `0`, output/submit/discard flags may contain only `BPF_RB_NO_WAKEUP` / `BPF_RB_FORCE_WAKEUP`, query flags must be one of the kernel `BPF_RB_*` selectors, including `BPF_RB_OVERWRITE_POS`, and `bpf_ringbuf_output` may use literal `0` data only when its size is also `0`. `cgroup-array` maps use `map-contains --kind cgroup-array` with a cgroup-array slot index; tc_action, tc, tcx, netkit, and lwt_* programs lower to `bpf_skb_under_cgroup(ctx, map, index)` for the current packet, while other programs lower to the base helper `bpf_current_task_under_cgroup(map, index)` for the current task. The raw helper spelling remains available as an escape hatch. `lpm-trie` uses the kernel's raw trie-key layout, so the key bytes must already begin with a `u32` prefix length followed by the trie payload.

Raw cgroup membership helper calls require `index` to be `0` through `u32::MAX`.

The current-task identity helpers are available as ordinary context fields on
tracing-style runtime contexts: `ctx.pid` / `ctx.tid`, `ctx.tgid`,
`ctx.uid`, and `ctx.gid` expose the split halves, while `ctx.pid_tgid` and
`ctx.uid_gid` expose the kernel-packed `u64` helper values directly. The
current-task cgroup ID is available as the ordinary `ctx.cgroup_id` field on
runtime-context programs. Ancestor IDs use a constant numeric cell-path level,
for example `ctx.ancestor_cgroup_id.0`; the level must be in `0..i32::MAX`, and
the projection returns the same scalar ID shape as `bpf_get_current_cgroup_id`.
Extension, syscall, and `struct_ops` callback
specs do not expose this field surface.

`ctx.ktime` remains the preferred ordinary timestamp surface. Specific
kernel clocks/counters are also available as ordinary fields:
`ctx.ktime_boot`, `ctx.ktime_tai`, and `ctx.jiffies` on runtime-context
programs, plus `ctx.ktime_coarse` on non-tracing runtime-context programs.
The corresponding modeled helper escape hatch forms remain available.
Pseudo-randomness is also available without raw helper spelling as either the
ordinary Nushell primitive `random int` or the context fields `ctx.random` /
`ctx.prandom_u32`.

`redirect-map` is the first-class XDP surface for `bpf_redirect_map`. It takes a literal map name plus a key, requires `--kind devmap`, `--kind devmap-hash`, `--kind cpumap`, or `--kind xskmap`, and returns the helper result directly so it can be the closure's final XDP action. `--flags` stays available for the helper's fallback return-code bits when the map lookup misses plus broadcast/exclude-ingress bits.

`adjust-packet` is the first-class packet-relayout surface. On XDP it takes a delta from pipeline input or a positional argument, requires exactly one of `--head`, `--meta`, or `--tail`, and lowers to the corresponding `bpf_xdp_adjust_*` helper while materializing the ambient context pointer automatically; XDP adjust `DELTA` must fit signed 32-bit range (`i32::MIN..=i32::MAX`). On `tc_action`, `tc`, `tcx`, `netkit`, `sk_skb`, and `sk_skb_parser`, `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` do the same for the skb relayout helpers; pull `LEN` must be `0` through `u32::MAX`.

`adjust-message` is the first-class `sk_msg` byte-window and reshaping surface. `adjust-message --apply BYTES` and `adjust-message --cork BYTES` lower to `bpf_msg_apply_bytes` and `bpf_msg_cork_bytes`. `adjust-message --pull START END [--flags N]`, `adjust-message --push START LEN [--flags N]`, and `adjust-message --pop START LEN [--flags N]` lower to `bpf_msg_pull_data`, `bpf_msg_push_data`, and `bpf_msg_pop_data`; byte counts, pull start/end, and push/pop start/len arguments must be `0` through `u32::MAX`, pull/push/pop flags are reserved and must be `0`, and pull ranges require `END > START`. The ambient message context pointer is materialized automatically and the helper result is returned directly.

`redirect` is the first-class packet redirect surface for XDP, tc_action, tc, tcx, and netkit. It takes an ifindex from pipeline input or a positional argument and returns the helper result directly; `IFINDEX` must be `0` through `u32::MAX`. Plain `redirect IFINDEX` lowers to `bpf_redirect`. `redirect --peer IFINDEX` lowers to `bpf_redirect_peer` on tc_action, `tc:...:ingress`, `tcx:...:ingress`, or netkit, and `redirect --neigh IFINDEX` lowers to the default-neighbor `bpf_redirect_neigh(IFINDEX, 0, 0, FLAGS)` form on tc_action/tc/tcx/netkit. `--flags` stays available for the helper's flags argument.

`redirect-socket` is the first-class socket redirect/selection surface for `sk_msg`, `sk_skb`, `sk_skb_parser`, and `sk_reuseport`. It takes a literal map name plus a key, requires `--kind sockmap` / `--kind sockhash` on message/SKB stream programs or `--kind reuseport-sockarray` on `sk_reuseport`, selects the appropriate helper from the current program type, and returns that helper result directly. On message/SKB stream programs, `--flags` is limited to `0` or `BPF_F_INGRESS`; on reuseport selection, `--flags` must be `0`.

Read-only closure captures now lower as real constants for supported types (`int`, `bool`, `string`, `binary`, `nothing`, constant records, numeric constant lists, and homogeneous fixed arrays of scalar/binary/record constants`) instead of only working when inlined manually. That means existing Nushell structure can keep driving compile-time positions such as generic map names, for example `let map_name = "seen_paths"; $ctx.arg0.f_path | map-put $map_name $ctx.pid --kind hash`. Reassigned captured bools, numeric scalars, strings, fixed binary values, numeric constant lists, homogeneous fixed arrays, and representable constant records now take the next step and lower as compiler-managed mutable globals backed by `.data` or `.bss`, so ordinary Nushell variable flow can express per-program state without dropping down to explicit maps for the smallest cases. Leading typed `mut` list initializers can also use homogeneous scalar/binary/record constants as fixed-array globals when the initializer provides the concrete length and layout, for example `mut entries: list<record<pid: int cpu: int>> = [{pid: 7, cpu: 2} {pid: 9, cpu: 3}]`; the same fixed-array layout is available for typed list fields nested inside typed record `mut` globals. That mutable path is still intentionally honest: it works for values with a real byte layout and tracked runtime metadata, and metadata-only record builders are accepted only when the compiler can derive a truthful naturally aligned fixed record layout, including nested record-builder fields, and materialize them on demand before the global store.

## Language Surface Policy

- Prefer ordinary Nushell syntax plus the small first-class eBPF command set (`emit`, `count`, `histogram`, `start-timer`, `stop-timer`, `read-str`, `read-kernel-str`, `adjust-packet`, `adjust-message`, `redirect`, `redirect-map`, `redirect-socket`, and `assign-socket`) whenever the operation has an honest language form. Ordinary Nushell primitives are preferred over helper wrappers too; `random int` and the supported stack-list/fixed-record aggregate commands lower directly through the compiler.
- Keep that permanent first-class surface intentionally small. Those commands should exist because they model real eBPF operations that do not already have a clear Nushell shape, not because every helper needs a bespoke wrapper.
- Prefer leading typed `mut` bindings for private compiler-managed globals. Use `global-define`, `global-get`, and `global-set` when you truly need an explicit shared name or a source-order-independent declaration.
- Treat `map-*` and `global-*` as convenience surface around concrete eBPF capabilities, not as a goal to invent a second parallel language when plain Nushell syntax would be clearer. They are justified when they name a real map/global resource directly; `map-define` is specifically the typed resource declaration path for key/value layouts and map capacity that ordinary operations cannot infer. They are not a template for growing new wrappers by default.
- Treat `helper-call` and `kfunc-call` as escape hatches for kernel ABI surface we have not yet lifted into a smaller, more idiomatic language primitive.
- Compiler-internal helper and kfunc modeling is permanent even if escape-hatch commands shrink later. The compiler still has to know signatures, legal program families, pointer/ref semantics, and verifier-facing rules.
- Callback-taking helper escape hatches can lower closure/block literals into modeled BPF subprogram pointers for `bpf_for_each_map_elem`, `bpf_timer_set_callback`, `bpf_find_vma`, `bpf_loop`, and `bpf_user_ringbuf_drain`. Their callback ABI is checked during lowering, type inference, verifier_types, and VCC. Source closures may declare a prefix of the ABI parameters when trailing callback arguments are unused; declaring more parameters than the ABI supplies is rejected. `bpf_loop` also enforces the kernel `BPF_MAX_LOOPS` iteration ceiling (`8 * 1024 * 1024`) before load. `bpf_for_each_map_elem` callbacks receive a non-null BTF-backed `bpf_map *` plus typed non-null key/value pointers when the map has a declared or pinned schema, so fields such as `$m.id` can be projected from the map argument. `bpf_find_vma` callbacks seed `task_struct *` and `vm_area_struct *` parameters as non-null BTF-backed kernel pointers when kernel BTF is available, so fields such as `$vma.vm_start` can be projected directly. `bpf_user_ringbuf_drain` seeds its dynptr callback argument as an initialized synthetic stack object. Timer helpers (`bpf_timer_init`, `bpf_timer_set_callback`, `bpf_timer_start`, and `bpf_timer_cancel`) require arg0 to be a `bpf_timer` field projected from a concrete hash, array, or lru-hash map value; `bpf_timer_init` also requires its map argument to name that same owning map, and timer callbacks receive a non-null BTF-backed `bpf_map *` plus typed non-null key/value pointers.
- Callback-taking kfunc escape hatches use the same source arity policy for modeled callback arguments. `bpf_wq_set_callback_impl` callbacks may omit unused trailing `(bpf_map*, key*, bpf_wq*)` parameters, while `bpf_rbtree_add_impl` callbacks may omit unused trailing node parameters; extra declared parameters are rejected before backend code generation.

## Commands

| Command | Description |
|---------|-------------|
| `ebpf attach` | Attach eBPF probe with closure |
| `ebpf spec` | Inspect parsed target metadata, aliases, parsed attach shape, context family, packet context kind, packet header fields/protocol views, direct packet-write support, concrete context argument and return-value surfaces when knowable, modeled context fields with type labels, pointer verifier facts, load guards, aggregate/direct/helper compatibility floors, direct/array/nested context load-shape metadata including direct/array read transforms, backing helpers with compatibility keys and inherited helper kernel floors where applicable, and nested direct/helper-backed projections, tracepoint payload fields with tracefs/fallback provenance, writable context surfaces with direct context-field keys plus backing helper/kfunc compatibility keys and version metadata where applicable, argument/return access mode, return aliases, capabilities, supported first-class intrinsic commands with helper floors, intrinsic context-field requirements, and map-kind floors for kind-sensitive redirect variants, section naming/target usage, struct_ops value/callback metadata, sleepable/BTF-callable metadata, kernel-target validation, live-attach/default-safety support, derived external-alpha status, and compatibility requirements; pass `--list` for all modeled program families |
| `ebpf detach` | Detach a probe by ID |
| `ebpf list` | List active probes |
| `ebpf counters` | Read counter map |
| `ebpf histogram` | Read histogram buckets |
| `ebpf stacks` | Read stack traces |
| `ebpf trace` | Read raw trace events |
| `ebpf setup` | Configure capabilities |

`ebpf spec` uses structured `attach_shape` records for attach-sensitive targets:
XDP mode/frags, perf-event source and period/frequency sampling,
socket-filter transport/family, netns-scoped sk_lookup/flow_dissector,
socket-map sk_msg/sk_skb hooks, TC/TCX ingress-vs-egress, TC action metadata,
Netkit endpoint, sk_reuseport mode, LWT hook, netfilter
family/hook/priority/defrag, cgroup device/sysctl/sock_ops plus
socket/SKB/sockopt/socket-address variants, lirc devices, syscall/iterator
programs, and struct_ops roots/callback family metadata. Probe-like targets
remain `generic` when the target string already carries all currently modeled
policy.

Context-field rows report direct/array/nested ABI load shapes when a field is
source-backed by the program context. Rows with an ABI load also report
`abi_field`, the modeled kernel-context field whose load shape is used; this is
usually the row's own field, but attach-sensitive `cgroup_sock_addr` aliases
such as `remote_ip4` or `local_ip4` can resolve to underlying ABI fields such
as `user_ip4` or `msg_src_ip4`. Direct loads also expose `direct_load_transform`
when the compiler changes the raw ABI value into the semantic value seen by
Nushell, for example big-endian address/protocol normalization, lirc mode/value
masking, and cgroup-device access/type extraction from `access_type`. Array
loads similarly expose `array_load_transform` for semantic array normalization
such as IPv6 address words converted from big-endian ABI order to host order;
this is separate from `array_load_normalize_big_endian`, which describes the
backend context-copy path.

For `struct_ops`, use `struct_ops:<value_type>` for object-level metadata and
`struct_ops:<value_type>.<callback>` for callback-level metadata such as
sleepable section selection and kernel-BTF callback context shape. Direct
callback targets are compile/dry-run metadata targets, not live attach targets;
emit callbacks through the enclosing `struct_ops:<value_type>` object.

`context_projections` is target-specific and only advertises projections that
are valid for the parsed attach shape. For example, socket fields or
helper-backed socket projections that are invalid on a particular hook are
omitted from the projection table; attempting to use them in a program still
produces the normal compiler diagnostic. Projection rows are emitted for
accepted context-root aliases as well as canonical roots, using
`source = context_field_root_alias` for direct fields reached through an alias
root. Projection rows include source-backed minimum kernels when known;
helper-backed rows also include an aggregate
compatibility floor, the selected helper, any generated field-read helper such
as `bpf_probe_read_kernel`, and each helper's own floor. Helper-call
projections such as `task.pt_regs.arg0` and
parameterized helper projections such as `ancestor_cgroup_id.N`,
`skb_ancestor_cgroup_id.N`, `sk.ancestor_cgroup_id.N`, or
`socket.ancestor_cgroup_id.N` use a non-negative `N` that fits `i32`,
`source = helper_call` and a null `offset`, because they are not direct
struct-field byte offsets.
`context_writes` rows report the assignment kind, whether the write requires a
fixed index, `abi_field` when the write maps to a modeled context ABI field,
the aggregate write-surface compatibility floor when known, the direct
context/write-only field floor, concrete direct/indexed/transformed store-shape
metadata when the write is a fixed context store, and any helper or kfunc used
by the write surface. Indexed store rows report the base offset, element count,
and whether each element is converted to big endian; transformed store rows
report the offset plus conversion such as `host-u32-to-big-endian` or
`host-port-to-big-endian-u32`. Known ABI-backed writes include separate
helper/kfunc minimum-kernel and source fields, plus nullable kfunc
maximum-exclusive windows and sources, so surfaces such as `ctx.reply`,
`ctx.mark`, `ctx.cb_flags`, `ctx.new_value`, `ctx.sk`, `ctx.sun_path`,
attach-sensitive socket-address aliases such as `ctx.remote_ip4`, and
context-pointer scalar field roots such as `ctx.flow_keys` can be inspected
before writing code that depends on them.
`intrinsics` rows include aggregate `compatibility_minimum_kernel` /
`compatibility_minimum_kernel_source` fields, aggregate `backing_helpers`, and
`context_field_requirements` when an intrinsic implies a context-field ABI
dependency. For example, `assign-socket` reports the target-specific `ctx:sk`
minimum kernel alongside its `bpf_sk_assign` helper floor, while the row-level
compatibility floor reports the later of those requirements.

## Ordinary Nushell Primitives (inside closures)

The compiler intentionally supports ordinary Nushell forms before adding new
helper-style commands. Current aggregate lowering is focused on values whose
eBPF layout and verifier bounds are explicit:

| Primitive | Supported eBPF subset |
|-----------|-----------------------|
| `where` | Stack-backed numeric lists with a closure predicate; scalar pipeline filtering also lowers to an early return when the predicate is false |
| `each` | Stack-backed numeric lists with a closure transform, preserving runtime list length; scalar pipeline transforms are also supported |
| `all` / `any` | Stack-backed numeric lists with a closure predicate, verifier-bounded constant-index reads, and Nushell empty-list identities |
| `take` | Stack-backed numeric lists and compile-time known fixed lists with a compile-time non-negative count, including metadata-only float-list outputs when folded by metadata consumers |
| `skip` | Stack-backed numeric lists and compile-time known fixed lists with a compile-time non-negative count, including metadata-only float-list outputs when folded by metadata consumers |
| `drop` | Stack-backed numeric lists and compile-time known fixed lists with a compile-time non-negative count removed from the end, including metadata-only float-list outputs when folded by metadata consumers |
| `reverse` | Stack-backed numeric lists, preserving runtime length with descending constant-index loads; compile-time known fixed lists are reversed as constants, including metadata-only float-list outputs when folded by metadata consumers |
| `uniq` | Stack-backed numeric lists, preserving first occurrences through verifier-bounded duplicate checks; compile-time known fixed lists are deduplicated as constants, including metadata-only float-list outputs when folded by metadata consumers |
| `sort` | Stack-backed numeric lists with capacity <= 16, using bounded compare/swap lowering; compile-time known fixed lists with boolean, integer, finite float, binary, or string elements are sorted as constants, including metadata-only float-list outputs when folded by metadata consumers; `--reverse` is supported |
| `compact` | Stack-backed numeric lists as an identity operation because numeric-list elements cannot be null or empty; compile-time known fixed lists are filtered as constants, with `--empty` also removing known empty strings/binaries/lists/records; metadata-only float-list outputs are supported when folded by metadata consumers; top-level column arguments are supported for compile-time known fixed lists of records |
| `find` | Stack-backed numeric lists with one numeric search argument, returning a bounded equality-filtered stack list; compile-time known fixed lists with one compile-time constant search argument, including metadata-only float-list outputs when folded by metadata consumers |
| `append` / `prepend` | Stack-backed numeric lists with scalar numeric items when the output fits the modeled capacity; compile-time known fixed lists with compile-time constant items, including metadata-only float-list outputs when folded by metadata consumers |
| `char` | Compile-time named characters using the first name argument and ignoring extra string rest arguments, `--unicode` hexadecimal string codepoints, and `--integer` codepoints, returning a fixed string; `--list`, pipeline input, mixed mode flags, and NUL-byte output are not supported |
| `seq` / `seq char` / `seq date` | Compile-time known integer one-, two-, or three-argument `seq` forms, producing a stack-backed numeric list up to 60 items; compile-time known float or mixed integer/float `seq` forms up to 60 items are supported as constant metadata when folded by metadata consumers, including list-transform chains; compile-time known two-argument ASCII `seq char` forms produce a fixed string list up to 60 items; deterministic `seq date` ranges with explicit `--begin-date` plus `--end-date`, positive integer `--days`, or positive integer `--periods`, optional compile-time `--input-format` / `--output-format`, optional positive integer day-count or duration `--increment`, and optional `--reverse` produce fixed string lists up to 60 items, with `--periods` then `--days` taking precedence over `--end-date`; default-today date ranges, negative/zero increments, pipeline input, extra arguments, materialized float output, and longer outputs are not supported |
| `fill` | Compile-time known string, int, float, or filesize scalar input or list input with optional compile-time `--width`, `--alignment`, and `--character`, returning padded fixed strings; runtime input, bool/null input, and closure-derived options are not supported |
| `is-empty` / `is-not-empty` | Stack-backed lists, tracked strings, literal null, literal list constants and fixed-layout list builders, and metadata-backed fixed records |
| `describe` | No-input, compile-time known values including metadata-only float/list values produced by folded commands or fixed-layout list builders, tracked runtime scalars, tracked strings, tracked records, and stack-backed numeric lists, producing a bounded tracked string with Nushell's type description |
| `bytes length` | Compile-time known binary input returning its byte length, or compile-time known list<binary> input returning a numeric list of byte lengths |
| `bytes starts-with` / `bytes ends-with` | Compile-time known binary input and binary pattern, returning a constant boolean |
| `bytes index-of` | Compile-time known binary input and non-empty binary pattern, returning the first byte index or `-1`; `--end` returns the last index, and `--all` returns a stack-backed numeric list of up to 60 non-overlapping match offsets, in reverse order when combined with `--end` |
| `bytes reverse` | Compile-time known binary input, returning a reversed binary value |
| `bytes build` | Compile-time known binary fragments and integer byte arguments, returning a binary value |
| `bytes at` | Compile-time known binary or list<binary> input and compile-time range using Nushell start/end bounds; scalar input returns a fixed binary slice, while materialized list output requires non-empty equal-length binary slices and empty or unequal list slices are supported when folded by `bytes collect`, `length`, or empty predicates |
| `bytes add` | Compile-time known binary or list<binary> input/data with optional non-negative `--index` and `--end`; scalar input returns a fixed binary value, while materialized list output requires non-empty equal-length binary values and empty or unequal list outputs are supported when folded by `bytes collect`, `length`, or empty predicates |
| `bytes remove` | Compile-time known binary input and non-empty binary pattern with optional `--all` and `--end`, returning a binary value |
| `bytes replace` | Compile-time known binary input, non-empty binary pattern, and binary replacement with optional `--all`, returning a binary value |
| `bytes collect` | Compile-time known list of binary values and optional binary separator, returning a fixed binary value |
| `bytes split` | Compile-time known binary input and non-empty binary/string separator; materialized lists require non-empty equal-length binary parts, while empty or unequal parts are supported when folded by `bytes collect`, `length`, or empty predicates |
| `str length` | Tracked strings and literal strings, returning the byte length tracked by the string buffer; compile-time known string-list input returns a numeric list, including `--grapheme-clusters` |
| `str starts-with` | Tracked strings with a compile-time literal prefix, lowered as a bounded stack-buffer prefix comparison; `--ignore-case` is supported for compile-time known input strings, and compile-time known string-list input returns a bool list |
| `str ends-with` | Tracked strings with a compile-time known input length and literal suffix, lowered as a fixed-offset stack-buffer suffix comparison; `--ignore-case` is supported for compile-time known input strings, and compile-time known string-list input returns a bool list |
| `str contains` | Tracked strings with a compile-time known input length and literal substring, lowered as bounded fixed-offset stack-buffer comparisons; `--ignore-case` is supported for compile-time known input strings, and compile-time known string-list input returns a bool list |
| `str index-of` | Tracked strings with a compile-time known input length and literal substring, returning the first byte index or `-1` through bounded fixed-offset comparisons; `--end`, compile-time `--range` using Nushell start/end bounds, and compile-time `--grapheme-clusters` are supported, and compile-time known string-list input returns a numeric list |
| `str join` | Compile-time known string input as a pass-through, or compile-time known string/int/float/filesize/duration/binary/bool/null/list/record-list input with an optional literal separator, returning a tracked string |
| `split chars` | Compile-time known scalar string input, returning a fixed string list of code points by default or grapheme clusters with `--grapheme-clusters`; compile-time known string-list input is supported as nested constant metadata when folded by `str join`, `length`, or empty predicates |
| `split list` | Compile-time known fixed-list input with a compile-time known literal separator, including metadata-only float nested-list outputs when folded by metadata consumers, or `--regex` string separator matching string/int/bool item text while preserving null/filesize/duration items as non-matches, and optional compile-time `--split on`/`before`/`after`, returning homogeneous fixed-layout groups; closure separators, runtime input lists, heterogeneous result group layouts, and `--regex` over binary/record/list/float items are not supported |
| `split row` | Compile-time known string or string-list input with a literal or `--regex` separator and optional non-negative compile-time `--number`, returning a fixed string list |
| `split words` | Compile-time known scalar string input, returning a fixed string list of Unicode words with optional non-negative compile-time `--min-word-length`; length is measured in UTF-8 bytes by default or grapheme clusters with `--grapheme-clusters`; compile-time known string-list input is supported as nested constant metadata when folded by `str join`, `length`, or empty predicates |
| `str expand` | Compile-time known string input with brace expressions, producing a fixed string list; empty expansion results and `--path` are supported |
| `str substring` | Compile-time known string or string-list input with one compile-time known explicit range argument using Nushell start/end bounds, with default/`--utf-8-bytes` byte indexes or `--grapheme-clusters` |
| `str replace` | Compile-time known string or string-list input with literal find/replacement arguments in the default first-substring replacement mode, `--all` substring replacement mode, or compile-time `--regex`/`--multiline` modes |
| `str trim` | Compile-time known string or string-list input in default, `--left`, `--right`, and single-character `--char` trim modes |
| `str downcase` / `str upcase` | Compile-time known string or string-list input in the default whole-string case-conversion mode |
| `str reverse` / `str capitalize` | Compile-time known string or string-list input in the default whole-string transform mode |
| `str camel-case` / `str kebab-case` / `str pascal-case` / `str screaming-snake-case` / `str snake-case` / `str title-case` | Compile-time known string or string-list input in the default whole-string case-conversion mode |
| `length` | Stack-backed numeric lists, compile-time known list constants and fixed-layout list builders, literal binary, and literal null values |
| `bits and` / `bits or` / `bits xor` | Integer scalar input and integer stack-backed or compile-time known lists with one integer target argument, plus compile-time known binary scalar input and fixed-layout binary lists with one compile-time binary target argument and optional `--endian native|little|big`; runtime binary input is not supported |
| `bits not` / `bits not --number-bytes 1|2|4|8` / `bits not --signed` | Compile-time known integer scalar/list input for default auto-width mode, plus integer scalar input and integer stack-backed or compile-time known lists for explicit `--number-bytes` and `--signed` modes; default auto-width matches Nushell's 1/2/4/8-byte selection for compile-time values, integer `--number-bytes` modes use Nushell-compatible sign-sensitive masking, and `--signed` returns signed two's-complement bit negation. Compile-time known binary scalar input and fixed-layout binary lists are supported with bytewise complement semantics, with `--signed` and `--number-bytes 1|2|4|8` accepted as no-ops for binary input; runtime binary input is not supported |
| `bits shl` / `bits shr` | Integer scalar input and integer stack-backed or compile-time known lists with one compile-time shift count. Explicit `--number-bytes 1|2|4` modes match Nushell's source-sign-sensitive truncation/sign-extension semantics, signed `--number-bytes 1|2|4` modes sign-extend the selected width, `--signed` with or without `--number-bytes 8` uses signed 64-bit shifts, and compile-time known default auto-width integer input selects Nushell's 1/2/4/8-byte width per value. Compile-time known unsigned `--number-bytes 8` integer input is supported when the result fits Nushell's integer range; runtime unsigned `bits shr --number-bytes 8` is supported with source-sign-sensitive arithmetic/logical right-shift behavior, while runtime unsigned `bits shl --number-bytes 8` and runtime default auto-width input are not supported because Nu may report out-of-range results. Compile-time known binary scalar input and fixed-layout binary lists are supported with whole-buffer big-endian bitstring shift semantics, counts from `0` through the input bit length, and `--signed` / `--number-bytes 1|2|4|8` accepted as no-ops for binary input. Runtime shift counts and runtime binary input are not supported |
| `bits rol` / `bits ror` | Integer scalar input and integer stack-backed or compile-time known lists with one compile-time rotate count. Explicit `--number-bytes 1|2|4` modes rotate within the selected width and match Nushell's source-sign-sensitive integer result, signed `--number-bytes 1|2|4` modes sign-extend the selected width, `--signed` with or without `--number-bytes 8` uses signed 64-bit rotates, and compile-time known default auto-width integer input selects Nushell's 1/2/4/8-byte width per value. Compile-time known unsigned `--number-bytes 8` integer input is supported when the result fits Nushell's integer range; runtime unsigned 8-byte and runtime default auto-width input are not supported. Compile-time known binary scalar input and fixed-layout binary lists are supported with whole-buffer big-endian bitstring rotate semantics, counts from `0` through the input bit length, and `--signed` / `--number-bytes 1|2|4|8` accepted as no-ops for binary input. Runtime rotate counts and runtime binary input are not supported |
| `math avg` | Compile-time known integer/float lists when the float result is folded by `fill`, and compile-time known homogeneous filesize/duration lists materialized as the corresponding unit type. Empty lists, mixed unit/numeric lists, runtime lists, and materialized numeric float averages are not supported |
| `math arccos` / `math arcsin` / `math arctan` | Compile-time known integer/float scalars and lists in default radians mode, or with optional `--degrees`/`-d` output conversion, when the finite float or list<float> result is folded by metadata-only consumers such as `fill` or `str join`. `math arccos` and `math arcsin` require input in `[-1, 1]`. Runtime input, non-finite float input, non-finite results, and materialized float/list<float> results are not supported |
| `math arccosh` / `math arcsinh` / `math arctanh` | Compile-time known integer/float scalars and lists when the finite float or list<float> result is folded by metadata-only consumers such as `fill` or `str join`. `math arccosh` requires input `>= 1`; `math arctanh` requires input in `(-1, 1)` so folded results stay finite. Runtime input, non-finite float input, non-finite results, and materialized float/list<float> results are not supported |
| `math cos` / `math sin` / `math tan` | Compile-time known integer/float scalars and lists in default radians mode, or with optional `--degrees`/`-d` input conversion, when the finite float or list<float> result is folded by metadata-only consumers such as `fill` or `str join`. Runtime input, non-finite float input, non-finite results, and materialized float/list<float> results are not supported |
| `math cosh` / `math sinh` / `math tanh` | Compile-time known integer/float scalars and lists when the finite float or list<float> result is folded by metadata-only consumers such as `fill` or `str join`. Runtime input, non-finite float input, non-finite results, and materialized float/list<float> results are not supported |
| `math exp` | Compile-time known integer/float scalars and lists when the finite float or list<float> result is folded by metadata-only consumers such as `fill` or `str join`. Runtime input, non-finite float input, non-finite results, and materialized float/list<float> results are not supported |
| `math ln` | Compile-time known positive integer/float scalars and lists when the finite float or list<float> result is folded by metadata-only consumers such as `fill` or `str join`. Runtime input, non-positive input, non-finite float input, non-finite results, and materialized float/list<float> results are not supported |
| `math log` | Compile-time known positive integer/float scalars and lists with one compile-time known positive base other than `1`, when the finite float or list<float> result is folded by metadata-only consumers such as `fill` or `str join`. Runtime input, non-positive input/base, base `1`, non-finite float input/base/results, and materialized float/list<float> results are not supported |
| `math sqrt` | Compile-time known non-negative integer/float scalars and lists when the float or list<float> result is folded by metadata-only consumers such as `fill`, `describe`, or `str join`. Runtime input, negative input, non-finite float input, and materialized float/list<float> results are not supported |
| `math variance` / `math stddev` | Compile-time known non-empty integer/float lists in default population mode or `--sample` mode when the finite float result is folded by metadata-only consumers such as `fill`. Sample mode requires at least two items. Runtime input, table/record input, non-finite float input, non-numeric list items, non-finite results, and materialized float results are not supported |
| `math sum` / `math product` / `math min` / `math max` | Stack-backed numeric lists with known non-empty length, compile-time known filesize/duration lists for `math sum`, and compile-time known integer/filesize/duration lists for `math min` and `math max` preserving the selected value type, plus compile-time known integer/float lists for `math sum` and `math product` when their float result is folded by `fill` and for `math min` and `math max` when the selected result is an integer or when a float result is folded by `fill`; empty-list input is rejected to match Nushell semantics, `math product` does not support filesize/duration input, and materialized float reducer results are not supported |
| `math median` | Compile-time known odd-length integer lists, compile-time known integer/float lists whose median is an integer or whose float median is folded by `fill`, compile-time known homogeneous filesize/duration lists including even-length unit medians, and stack-backed numeric lists with known odd length up to 16 items, returning the integer or unit median; empty lists, unknown-length runtime lists, runtime even-length numeric lists, and materialized float median results are not supported |
| `math mode` | Compile-time known integer lists, returning a sorted stack-backed numeric list of up to 60 most-frequent values, and stack-backed numeric lists with capacity <= 16 using bounded sort/count lowering; empty lists return an empty list, while non-integer compile-time items are not supported |
| `math abs` | Compiler-known integer scalar input, compile-time known integer-list input, and stack-backed numeric lists, returning integer/list absolute values with Nushell's wrapping `i64::MIN` behavior; compile-time list output is limited to 60 values. Compile-time known finite float scalars and integer/finite-float lists are supported when float results are folded by metadata-only consumers such as `fill` or `str join`; materialized float results and non-finite float input are not supported |
| `math ceil` / `math floor` / `math round` | Integer scalar input and integer stack-backed lists as identity operations, plus compile-time known integer/float scalar or list input returning integer results. `math round --precision <int>` / `-p <int>` supports compile-time known integer/float scalars and lists when the finite float or list<float> result is folded by metadata-only consumers such as `fill` or `str join`; materialized precision-mode float results and runtime float inputs are not supported in eBPF |
| `first` / `last` | Scalar first/last element access for stack-backed numeric lists and compile-time known fixed lists, including metadata-only float scalars when folded by metadata consumers; counted forms rebuild bounded prefix/suffix stack-list slices for stack-backed numeric lists and constant-fold compile-time known fixed lists, including metadata-only float-list outputs when folded by metadata consumers |
| `get` | Stack-backed numeric-list indexing, constant-index item projection from compile-time known fixed lists, including metadata-only scalar projections when folded by metadata consumers, top-level metadata-backed fixed-record field projection, typed context / BTF-backed pointer field projection with compiler-visible field paths such as `$ctx | get sk | get family`, and typed kernel/user pointer numeric indexing; list literal indexes may be literal cell paths |
| `select` / `reject` | Metadata-backed fixed records, materialized into a fresh fixed-layout record |
| `rename` | Positional top-level field renames, compile-time `--column {old: new}` mappings, and `--block` closures made only of no-argument known string transform commands for metadata-backed fixed records |
| `merge` | Metadata-backed fixed records with one metadata-backed record argument, preserving Nushell overwrite and append field semantics |
| `columns` | Metadata-backed fixed records, producing a fixed string list of field names in record field order, including metadata-only list-transform chains when folded by metadata consumers |
| `values` | Metadata-backed fixed records whose fields are numeric scalar values, including bool/null as `1`/`0`, producing a stack-backed numeric list in record field order; compile-time known homogeneous fixed-layout values produce a fixed list; homogeneous finite float record values are supported as metadata-only lists when folded by metadata consumers |
| `transpose` | Compile-time known record values, producing Nushell-style rows with default `column0` / `column1` names or the first two positional output column names; `--ignore-titles` produces one-column rows named `column0` or by the first positional output name. Homogeneous row layouts can materialize as fixed arrays, while mixed row value layouts are supported when folded by metadata-only fixed-list consumers such as `get` or `length`; table input, runtime-valued records, and other transpose flags are not supported |
| `insert` / `update` / `upsert` | Top-level metadata-backed fixed-record fields with non-closure replacement values, preserving Nushell existing/missing-field behavior |
| `default` | Compiler-known null/empty scalar replacement and metadata-backed record missing/null field replacement; closure default values and runtime nullable-pointer defaults are rejected |
| `random int` | BPF pseudo-random integer generation, including the zero-argument form and compile-time bounded ranges covering at most `2^32` values |

These are language primitives in the compiled closure subset, not permanent
helper wrappers. If a Nushell command would require dynamic allocation,
unbounded iteration, dynamic dispatch, or a layout the compiler cannot prove,
it remains outside the eBPF subset until a verifier-friendly lowering exists.

## First-Class, Resource, and Escape-Hatch Commands (inside closures)

| Command | Description |
|---------|-------------|
| `emit` | Send value to userspace |
| `count` | Increment counter by key |
| `histogram` | Add value to log2 histogram |
| `start-timer` | Record start timestamp |
| `stop-timer` | Calculate elapsed time |
| `read-str` | Read string from user memory (`--max-len` to cap, default 128) |
| `read-kernel-str` | Read string from kernel memory (`--max-len` to cap, default 128) |
| `adjust-packet` | Packet relayout (`xdp`: `--head` / `--meta` / `--tail`; `tc_action` / `tc` / `tcx` / `netkit` / `sk_skb` / `sk_skb_parser`: `--head` / `--tail` / `--pull` / `--room`) |
| `adjust-message` | `sk_msg` byte-window and reshaping control (`--apply`, `--cork`, `--pull`, `--push`, or `--pop`) |
| `redirect` | XDP/tc_action/tc/tcx/netkit redirect by ifindex (`--peer` and `--neigh` select cls_act helper variants; optional `--flags`) |
| `redirect-map` | XDP redirect through a named devmap/devmap-hash/cpumap/xskmap (`--kind` required; optional `--flags`) |
| `redirect-socket` | `sk_msg`/`sk_skb`/`sk_skb_parser` redirect through a named sockmap/sockhash, or `sk_reuseport` selection through a reuseport-sockarray (`--kind` required; `--flags` optional but must be `0` for reuseport) |
| `helper-call` | Escape hatch: call a modeled BPF helper by literal name, such as `bpf_get_current_pid_tgid` |
| `kfunc-call` | Escape hatch: call a typed kernel kfunc by literal name, resolved from kernel BTF when possible |
| `global-define` | Declare a named compiler-managed program global when a leading typed `mut` binding is not enough; `--zero` uses a runtime exemplar, and `--type` declares an explicit scalar/`bytes:N`/`string:N`/`list:int:N` (alias `list:i64:N`)/`array{type:N}`/nested `record{field:type,...}` layout either zero-initialized or from a compile-time constant initializer |
| `global-get` | Load a named compiler-managed program global declared with `global-define` or inferred from `global-set` |
| `global-set` | Store the pipeline input into a named compiler-managed program global |
| `map-define` | Declare named generic map key/value schemas with `--key-type` and `--value-type`, plus optional capacity with `--max-entries`, including aggregate keys and fixed-layout values with verifier-managed fields such as `bpf_timer`, `bpf_spin_lock`, `bpf_wq`, `bpf_refcount`, and `kptr:TYPE` |
| `map-get` | Look up a value pointer in a named generic or local-storage map |
| `map-put` | Insert or update a value in a named generic map, or update a sockmap/sockhash from `sock_ops` |
| `map-delete` | Delete a key or local-storage entry from a named map |
| `map-contains` | Test lookup-map membership for a key, local-storage presence for an owner object, bloom-filter membership for a value, or cgroup-array membership for an index |
| `map-push` | Push the pipeline input into a named queue, stack, or bloom-filter map |
| `map-peek` | Peek a maybe-null value pointer from a named queue or stack map |
| `map-pop` | Pop a maybe-null value pointer from a named queue or stack map |

`kfunc-call` is intentionally an escape hatch. The compiler models signatures,
pointer/ref semantics, and the program-specific kfunc surfaces it knows about,
but exact kfunc availability is still kernel-version and program-type specific;
the kernel verifier remains the final authority for unmodeled kfunc allowlists.
`ebpf spec` reports modeled kfunc call surfaces with argument kinds,
pointer-argument rules, ref acquire/release families, release argument indexes,
and source-backed kernel-version metadata when those facts are known.
Compiled program and object metadata exposes the derived helper and kfunc names
actually present in bytecode/source lowering so compatibility summaries can be
audited without treating helper wrappers as language surface.
Known kfuncs that return named kernel pointers preserve those pointer types
through locals, and their fields can be projected when kernel BTF is available;
for example, a null-checked `bpf_task_acquire` result can read `$task.pid`
before releasing the reference. For kfuncs not yet present in the compiler's
static table, kernel BTF can provide the fallback arity, pointer/scalar
argument classes, exact pointer-argument pointee checks for named struct
targets, and exact return type; pointer returns from that path can use the same
BTF-backed field projection during local compilation, with live availability
still left to the kernel verifier.
For raw object and graph kfuncs, operands that map to verifier-rewritten
`__ign` metadata parameters must be known zero in source; the kernel replaces
them during load with the appropriate BTF metadata when the call is valid.

Stack trace ID collection should normally use first-class context fields: `$ctx.kstack` for kernel stacks and `$ctx.ustack` for user stacks. The backing `bpf_get_stackid` helper is constrained to tracing/perf-style program families and stack-trace maps, with flags limited to the skip field plus `BPF_F_USER_STACK`, `BPF_F_FAST_STACK_CMP`, and `BPF_F_REUSE_STACKID`. `bpf_get_stack` remains available through `helper-call` for custom buffers, maps, and flags, and accepts a stack/map buffer with a size fitting `0..=u32::MAX`; literal `0` may be used for `BUF` only when `SIZE` is also `0`. `bpf_get_task_stack` is also modeled for task-pointer inputs such as `ctx.task`, with the same stack/map output-buffer and `0..=u32::MAX` size checks. Stack-copy helper flags are limited to the skip field plus `BPF_F_USER_STACK` and `BPF_F_USER_BUILD_ID`; `BPF_F_USER_BUILD_ID` also requires `BPF_F_USER_STACK`.
Perf-event counter snapshots should normally use `ctx.perf_counter`, `ctx.perf_enabled`, and `ctx.perf_running`; the backing `bpf_perf_prog_read_value` helper is modeled and constrained to `perf_event` programs, with its raw `BUF_SIZE` argument fixed to `24` bytes for `struct bpf_perf_event_value`.
Perf-event-array counter reads are also modeled through `helper-call "bpf_perf_event_read" MAP FLAGS` and `helper-call "bpf_perf_event_read_value" MAP FLAGS BUF 24`; both require perf-event-array maps, require flags to fit `BPF_F_INDEX_MASK` / `BPF_F_CURRENT_CPU` (`0xffffffff`), and the value form requires a 24-byte `struct bpf_perf_event_value` buffer.
Branch-stack helpers are modeled for escape-hatch use through `helper-call`. The perf-event-only `bpf_read_branch_records` helper includes its context argument, stack/map output buffer, zero-size query behavior, `0..=u32::MAX` size checks, and flags limited to `0` or `BPF_F_GET_BRANCH_RECORDS_SIZE`. The base `bpf_get_branch_snapshot` helper uses a stack/map `perf_branch_entry` buffer, accepts a null buffer only with size `0`, requires size to fit `0..=u32::MAX`, and requires reserved flags to be `0`.
Signal helpers are modeled as explicit escape hatches too: `helper-call "bpf_send_signal" SIG` targets the current process, and `helper-call "bpf_send_signal_thread" SIG` targets the current thread. Raw signal helper calls require `SIG` to be `0` through `u32::MAX`. They are intentionally not lifted into a first-class command because they have visible side effects.
Current-task identity helpers remain available through context fields such as `ctx.comm`, but the raw `helper-call "bpf_get_current_comm" BUF SIZE` spelling is also modeled for custom stack/map buffers. `SIZE` must be positive, fit `1..=u32::MAX`, and fit the destination buffer.
Per-CPU kernel symbol helpers are modeled for explicit escape-hatch use: `helper-call "bpf_per_cpu_ptr" PERCPU_PTR CPU` returns a nullable kernel pointer for the requested CPU, while `helper-call "bpf_this_cpu_ptr" PERCPU_PTR` returns a non-null kernel pointer for the current CPU. `PERCPU_PTR` must already be a trusted kernel per-CPU pointer, such as a pointer derived from a kernel BTF symbol path; stack and map pointers are rejected. The explicit `CPU` argument must fit `0..=u32::MAX`.
Userspace memory copy helpers are modeled for explicit `helper-call` use: `bpf_copy_from_user` requires a stack/map destination buffer and a typed userspace source pointer, while `bpf_copy_from_user_task` also requires a `task_struct *` argument such as `ctx.task` and reserved flags `0`. Their destination size may be `0`, but nonzero sizes must fit the output buffer, and the helper ABI caps `SIZE` to `u32::MAX`. `bpf_probe_write_user` is also modeled for tracing/LSM/perf escape-hatch use with a typed userspace destination pointer, stack/map source buffer, and `SIZE = 1..=u32::MAX`. It remains a hazardous debugging-only kernel helper; lockdown, capability, and user-context restrictions are still enforced by the kernel at load/attach/runtime.
Kprobe error injection is modeled through `helper-call "bpf_override_return" CTX RC` on entry kprobe-style surfaces (`kprobe`, `kprobe.multi`, and `ksyscall`). The compiler checks the raw context pointer shape, but the kernel still enforces `CONFIG_BPF_KPROBE_OVERRIDE`, GPL/license constraints, and the target function's `ALLOW_ERROR_INJECTION` eligibility.
TCP congestion-control struct_ops callbacks can use `helper-call "bpf_tcp_send_ack" TP RCV_NXT`, where `TP` must be a typed socket/TCP kernel pointer such as `struct tcp_sock *`, and `RCV_NXT` must fit `0..=u32::MAX`. The generic program-type policy treats this as a `struct_ops` helper, and full `ProgramSpec` contexts further narrow it to `tcp_congestion_ops` callbacks, matching the upstream TCP congestion helper surface for this helper.
Syscall programs can use the modeled syscall helper escape hatches `helper-call "bpf_sys_bpf" CMD ATTR ATTR_SIZE`, `helper-call "bpf_btf_find_by_name_kind" NAME NAME_SIZE KIND 0`, `helper-call "bpf_sys_close" FD`, and `helper-call "bpf_kallsyms_lookup_name" NAME NAME_SIZE 0 RES`. `ATTR` and `RES` must be stack/map-backed buffers, while `NAME` must be stack/map-backed unless the helper explicitly uses a zero size; `CMD` must fit nonnegative `int` width, `ATTR_SIZE` must fit `1..=u32::MAX`, `bpf_btf_find_by_name_kind` `NAME_SIZE` must fit `1..=i32::MAX`, `bpf_kallsyms_lookup_name` `NAME_SIZE` must fit `0..=i32::MAX`, `KIND` and `FD` must fit `u32`, and `RES` must cover an 8-byte `u64`. Live attach for `syscall:*` remains unsupported.
String formatting through `helper-call "bpf_snprintf" STR STR_SIZE FMT DATA DATA_LEN` is modeled as a raw escape hatch. `STR` and `DATA` must be stack/map-backed buffers unless their paired sizes are `0`, where literal `0` buffers are accepted; `FMT` must be a map/rodata-backed format string rather than a mutable stack string, `STR_SIZE` must fit `0..=u32::MAX`, and `DATA_LEN` must be a multiple of 8 capped to `MAX_BPRINTF_VARARGS * 8` (`96` bytes). `helper-call "bpf_trace_printk" FMT FMT_SIZE` and `helper-call "bpf_trace_vprintk" FMT FMT_SIZE DATA DATA_LEN` are also modeled for trace-debug formatting, with stack/map-backed format buffers, `FMT_SIZE = 1..=u32::MAX`, and `DATA_LEN` capped to `96` bytes as a nonnegative multiple of 8 for `trace_vprintk`; `trace_vprintk` `DATA` may be literal `0` only when `DATA_LEN` is also `0`. BTF-backed formatting is modeled through `helper-call "bpf_snprintf_btf" STR STR_SIZE BTF_PTR 16 FLAGS`, where `STR_SIZE` must fit `1..=u32::MAX`, `BTF_PTR` is a stack/map-backed 16-byte `struct btf_ptr` record, and `FLAGS` may only contain supported `BTF_F_*` bits (`0x0f`).
Iterator seq-file output is modeled through `helper-call "bpf_seq_write" SEQ DATA LEN`, `helper-call "bpf_seq_printf" SEQ FMT FMT_SIZE DATA DATA_LEN`, and `helper-call "bpf_seq_printf_btf" SEQ BTF_PTR 16 FLAGS` on `iter:*` programs. `SEQ` must be a kernel `seq_file *` value, `FMT`, `DATA`, and `BTF_PTR` must be stack/map-backed buffers, except `bpf_seq_write` may use `0` for `DATA` when `LEN` is also `0`, and `bpf_seq_printf` may use `0` for `DATA` when `DATA_LEN` is also `0`. `FMT_SIZE` must fit `1..=u32::MAX`, `LEN` must fit `0..=u32::MAX`; `DATA_LEN` must be a multiple of 8 capped to `96` bytes for `bpf_seq_printf`, and `FLAGS` may only contain modeled `BTF_F_*` bits (`0x0f`).
Path formatting through `helper-call "bpf_d_path" PATH BUF SIZE` is modeled for kernel `struct path *` inputs and stack/map output buffers. When a BTF-backed context exposes a terminal `struct path` field such as `$ctx.arg0.f_path` on file hooks, ordinary field access still has value semantics, but helper/kfunc ABI calls that require a kernel `struct path *` use the original kernel field address. `helper-call` requires that path argument to be written explicitly; a piped value is not prepended when additional explicit helper arguments are present. The newer `kfunc-call "bpf_path_d_path" PATH BUF SIZE` follows the same pointer and buffer rules, and the piped kfunc form is also accepted, for example `$ctx.arg0.f_path | kfunc-call "bpf_path_d_path" $buf 64`. The compiler checks pointer spaces and helper buffer sizes in `0..=u32::MAX` or positive kfunc buffer sizes as appropriate; the kernel still enforces attach-target allowlists.
LSM binary-parameter options can be set through `helper-call "bpf_bprm_opts_set" BPRM FLAGS` on LSM programs. `BPRM` must be a kernel `linux_binprm *` such as the argument exposed by `lsm:bprm_check_security`; `FLAGS` may only contain modeled `BPF_F_BPRM_*` bits (`0x01`, currently `BPF_F_BPRM_SECUREEXEC`).
IMA hash helpers are modeled on the sleepable LSM helper surface: `helper-call "bpf_ima_inode_hash" INODE DST SIZE` accepts a kernel `inode *`, and `helper-call "bpf_ima_file_hash" FILE DST SIZE` accepts a kernel `file *`. `DST` must be a stack/map output buffer and `SIZE` must fit `1..=u32::MAX`. The compiler requires `lsm.s` plus a modeled sleepable LSM hook such as `file_open`; plain `lsm`, `lsm_cgroup`, and non-sleepable hooks are rejected before load.
Cgroup return-value helpers are modeled for explicit `helper-call` use on the kernel-supported cgroup hooks: `bpf_get_retval` takes no arguments and `bpf_set_retval` takes a scalar return value in signed `int` range (`i32::MIN..=i32::MAX`). The compiler rejects cgroup skb, sock_ops, and cgroup_sock_addr recvmsg/getpeername/getsockname surfaces to match the kernel helper allowlist.
TC-family programs can call `helper-call "bpf_skb_cgroup_classid" CTX` to retrieve the cgroup v1 net_cls classid from the packet's associated socket. This TC/TCX/Netkit skb helper is distinct from `ctx.cgroup_classid`, which lowers to `bpf_get_cgroup_classid`.
Socket lookup helpers `bpf_sk_lookup_tcp`, `bpf_sk_lookup_udp`, and `bpf_skc_lookup_tcp` are modeled for explicit `helper-call` use with stack/map tuple buffers, known tuple sizes exactly `sizeof(tuple->ipv4)` (`12`) or `sizeof(tuple->ipv6)` (`36`), and reserved flags `0`; ordinary `ctx.sk.*` projections avoid spelling these helpers directly. Socket-cast helpers such as `bpf_skc_to_tcp_sock`, `bpf_skc_to_tcp6_sock`, `bpf_skc_to_mptcp_sock`, and `bpf_skc_to_unix_sock` are also modeled as escape hatches for typed kernel socket pointers, with nullable typed returns and socket-ref provenance checks.
Raw map-value spin locks are modeled through `helper-call "bpf_spin_lock" LOCK_PTR` and `helper-call "bpf_spin_unlock" LOCK_PTR` on non-tracing, non-socket-filter helper-capable program families. `LOCK_PTR` must be a non-null map-value pointer projected from a `bpf_spin_lock` field declared through a map value schema, for example `map-define locks --kind hash --value-type 'record{lock:bpf_spin_lock,counter:u64}'`. For maps with declared value layouts, object BTF emits a typed `value` member so the kernel can see verifier-managed fields; synthetic source-level padding is kept in the value size but omitted from BTF members. The compiler rejects impossible map-value schemas early: `bpf_spin_lock` must be a single top-level 4-byte-aligned field in a hash or array map, `bpf_timer` must be a single 8-byte-aligned field in a hash, array, or lru-hash map, `bpf_wq`, `bpf_refcount`, and `kptr:TYPE` fields must be top-level slots in hash, array, or lru-hash maps with the kernel-required alignment, and graph roots declared as `bpf_list_head:TYPE:FIELD[:record{...}]` or `bpf_rb_root:TYPE:FIELD[:record{...}]` must be top-level 8-byte-aligned fields. Bare graph root/node tokens are still rejected. Source-level `record{...}` specs naturally align these fields, while externally seeded schemas are still validated as provided. The compiler models the verifier lifetime rules: only one `bpf_spin_lock` may be held, unlock requires a matching lock on all paths, graph-root list/rbtree kfuncs require a held `bpf_spin_lock` from the same map lookup root or a repeated same-map/same-key lookup root when both pointers carry provenance, ordinary helper calls other than `bpf_spin_unlock`, non-allowlisted kfunc calls, and subfunction calls are rejected while a kernel lock is held, and every return path must release it. Resource spin-lock kfuncs such as `kfunc-call "bpf_res_spin_lock" LOCK_PTR` are also modeled as raw escape hatches: when the pointee type is known, `LOCK_PTR` must be a trusted kernel pointer to `struct bpf_res_spin_lock`, not an arbitrary kernel object such as `task_struct *`. The lock-held kfunc allowlist follows the kernel verifier: graph API kfuncs, `bpf_iter_num_*`, and `bpf_res_spin_*` may run in a lock-held region because the kernel uses them to manage verifier-owned objects and locks.
Raw dynptr helper and kfunc escape hatches are partially modeled. `bpf_dynptr_from_mem`, `bpf_copy_from_user_dynptr`, `bpf_copy_from_user_task_dynptr`, `bpf_copy_from_user_task_str_dynptr`, `bpf_dynptr_from_xdp`, and `bpf_dynptr_from_skb` initialize 16-byte stack-slot-base dynptr objects, while `bpf_dynptr_read`, `bpf_dynptr_write`, `bpf_dynptr_data`, `bpf_dynptr_size`, `bpf_dynptr_adjust`, `bpf_dynptr_slice`, `bpf_dynptr_slice_rdwr`, `bpf_dynptr_memset`, `bpf_dynptr_copy`, `bpf_dynptr_clone`, `bpf_dynptr_is_null`, and `bpf_dynptr_is_rdonly` require initialized dynptr objects as appropriate. Packet dynptr kfuncs are program-family gated: `bpf_dynptr_from_xdp` is XDP-only, while `bpf_dynptr_from_skb` is available on skb-backed socket-filter, LWT, TC action, TC/TCX/Netkit, cgroup_skb, sk_skb, netfilter, and BPF tracing programs with an available `sk_buff` argument. The compiler reports program-specific compatibility floors for that kfunc: Linux 6.4 on the original skb-backed packet family and Linux 6.12 on fentry/fexit/fmod_ret/tp_btf tracing surfaces. On netfilter, pass `$ctx.skb`; on tracing programs, pass a typed `sk_buff` / `__sk_buff` context argument projection. The compiler accepts the kernel's `sk_buff` / `__sk_buff` projection alias for this kfunc. Ringbuf dynptr helpers `bpf_ringbuf_reserve_dynptr`, `bpf_ringbuf_submit_dynptr`, and `bpf_ringbuf_discard_dynptr` add a separate reservation obligation: every reserved dynptr stack slot must be submitted or discarded on all paths, release helpers only accept live ringbuf dynptr reservations, and release consumes the dynptr. Bind by-reference stack objects to locals when their lifecycle spans multiple helper/kfunc calls: `let d = $rec.d; ... $d ...` tracks one mutable stack object, while repeated `$rec.d` projections are ordinary value projections and do not share lifecycle state. The compiler enforces stack-slot-base dynptr arguments, map/stack buffer bounds, nonnegative read/write/from-mem lengths where literal `0` memory buffers are accepted only with length `0`, positive reservation lengths, `bpf_ringbuf_reserve_dynptr` sizes in `1..=u32::MAX`, zero flags for packet dynptr kfunc constructors, reserved/wakeup flag ranges, double-release rejection, and constant `bpf_dynptr_data` / slice lengths. Dynptrs are not valid map-value schema fields; use stack-slot dynptr helper or kfunc arguments instead.
TCP syncookie helpers `bpf_tcp_check_syncookie` and `bpf_tcp_gen_syncookie` require IP and TCP header lengths of at least 20 bytes capped to `u32::MAX`. Raw syncookie helpers `bpf_tcp_raw_gen_syncookie_ipv4`, `bpf_tcp_raw_gen_syncookie_ipv6`, `bpf_tcp_raw_check_syncookie_ipv4`, and `bpf_tcp_raw_check_syncookie_ipv6` are modeled on XDP/TC-style programs for packet-header pointers. IPv4 helpers require a 20-byte IP header, IPv6 helpers require a 40-byte IP header, check helpers require a 20-byte TCP header, and raw generation sizes the TCP header from `TH_LEN` in `0..=u32::MAX`; literal `0` may be used for `TH` only when `TH_LEN` is also `0`.
Namespace-aware PID/TGID reads are available through `helper-call "bpf_get_ns_current_pid_tgid" DEV INO NSDATA 8`, where `NSDATA` is an 8-byte stack/map buffer containing `pid` and `tgid` as two `u32` values.
String-to-integer parsing helpers `bpf_strtol` and `bpf_strtoul` are modeled for escape-hatch use with stack/map input buffers, positive input lengths in `1..=u32::MAX`, 8-byte stack/map result slots, and base-selector flags restricted to `0`, `8`, `10`, or `16`. `bpf_strncmp` is also modeled as an escape hatch: `S1` must be a stack/map buffer with positive `S1_SIZE` in `1..=u32::MAX`, while `S2` must be a read-only map/rodata string.
Raw probe-read helpers such as `bpf_probe_read_user`, `bpf_probe_read_kernel`, and their string variants accept `SIZE = 0` through `u32::MAX`; nonzero sizes require stack/map destination buffers and source pointers in the helper-specific address space, while `SIZE = 0` may use null destination or source pointers. Legacy `bpf_probe_read_str` is modeled for escape-hatch compatibility on the same tracing/LSM/perf surfaces as legacy `bpf_probe_read`, but normal string reads should use `read-str` or `read-kernel-str` so the compiler can choose the explicit user/kernel helper.
BPF packet-output helpers `bpf_skb_output` and `bpf_xdp_output` are modeled for tracing/perf-style programs that receive typed `sk_buff` / `xdp_buff` packet-object pointers, such as a BTF-backed `$ctx.arg0` projection on an fentry/fexit/tp_btf target. Raw tracing `$ctx` is the trampoline wrapper, not the packet object, and is rejected for these helpers. They use perf-event-array maps, flags in `0..=0xffffffff` for a `BPF_F_INDEX_MASK` index or `BPF_F_CURRENT_CPU`, and stack/map data buffers sized by the helper `size` argument; literal `0` data is accepted only when `size` is also `0`. They are not treated as ordinary XDP/TC packet-program helpers.
Socket lookup helpers `bpf_sk_lookup_tcp`, `bpf_sk_lookup_udp`, and `bpf_skc_lookup_tcp` require known `tuple_size` constants: `12` for IPv4 tuples or `36` for IPv6 tuples. They also require `netns` in signed 32-bit range (`i32::MIN..=i32::MAX`) and reserved flags set to `0`.
BTF-backed tracing argument count is available as `ctx.arg_count` on program types where the kernel permits `bpf_get_func_arg_cnt`; LSM cgroup programs expose function arguments but not `ctx.arg_count`. The lower-level `bpf_get_func_arg`, `bpf_get_func_ret`, and `bpf_get_func_arg_cnt` helpers are modeled for explicit `helper-call` use when fixed `ctx.argN` / `ctx.retval` projections are not the right fit. The explicit `bpf_get_func_arg` argument index must fit `0..=u32::MAX`.

## Discovering Tracepoints

```bash
# List tracepoint categories
ls /sys/kernel/tracing/events/

# List syscall tracepoints
ls /sys/kernel/tracing/events/syscalls/

# View tracepoint fields
cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
```

Tracepoint field names come from tracefs format files. If those files are not
readable in the current environment, syscall tracepoints may fall back to the
generic syscall payload shape: `ctx.id` plus fixed-array `ctx.args`. For modeled
common syscall-entry tracepoints, the fallback also exposes source-known named
argument aliases over those ABI slots, such as `ctx.dfd`, `ctx.filename`,
`ctx.flags`, and `ctx.mode` for `syscalls/sys_enter_openat`, or `ctx.usize`
for `syscalls/sys_enter_openat2` matching the kernel argument name. Socket
syscall fallbacks also expose source-known names for common socket entry
tracepoints such as `sys_enter_socket`, `sys_enter_bind`, `sys_enter_connect`,
`sys_enter_sendto`, `sys_enter_recvfrom`, `sys_enter_setsockopt`,
`sys_enter_getpeername`, and `sys_enter_recvmmsg`. Path-oriented syscall
fallbacks also expose common stat,
open, permission, ownership, and pathname operation aliases such as
`sys_enter_newfstatat`, `sys_enter_statx`, `sys_enter_open`,
`sys_enter_creat`, `sys_enter_fchmodat`, `sys_enter_fchownat`,
`sys_enter_chdir`, `sys_enter_getcwd`, `sys_enter_readlinkat`,
`sys_enter_statfs`, `sys_enter_getdents64`, `sys_enter_name_to_handle_at`,
`sys_enter_mknod`, `sys_enter_link`, `sys_enter_linkat`, `sys_enter_rename`,
`sys_enter_renameat2`, Linux 6.6+ `sys_enter_fchmodat2`, and Linux 6.17+
`sys_enter_file_getattr` / `sys_enter_file_setattr`.
Extended-attribute fallbacks expose aliases for
`sys_enter_setxattr`, `sys_enter_fsetxattr`, `sys_enter_getxattr`,
`sys_enter_fgetxattr`, `sys_enter_listxattr`, `sys_enter_flistxattr`,
`sys_enter_removexattr`, `sys_enter_fremovexattr`, and Linux 6.13+
`sys_enter_setxattrat` / `sys_enter_getxattrat` / `sys_enter_listxattrat` /
`sys_enter_removexattrat`.
Mount API fallbacks include Linux 5.2+ `sys_enter_open_tree`,
`sys_enter_move_mount`, `sys_enter_fsopen`, `sys_enter_fsconfig`,
`sys_enter_fsmount`, `sys_enter_fspick`, Linux 5.12+ `sys_enter_mount_setattr`,
Linux 6.8+ `sys_enter_statmount` / `sys_enter_listmount`, and Linux 6.15+
`sys_enter_open_tree_attr`.
Legacy filesystem administration fallbacks expose source-known aliases for
`sys_enter_mount`, `sys_enter_umount`, `sys_enter_pivot_root`,
`sys_enter_quotactl`, Linux 5.14+ `sys_enter_quotactl_fd`, and
`sys_enter_ustat`. Process
control fallbacks expose stable aliases for entry tracepoints such as
`sys_enter_execveat`, `sys_enter_wait4`, `sys_enter_setns`, module and kexec
calls such as `sys_enter_init_module` and `sys_enter_kexec_file_load`,
`sys_enter_reboot`, `sys_enter_acct`, and process creation calls such as
`sys_enter_clone`, `sys_enter_fork`, and `sys_enter_vfork`. File-descriptor
and event fallbacks expose aliases for common entry tracepoints such as
`sys_enter_lseek`, `sys_enter_fallocate`, `sys_enter_sync_file_range`,
`sys_enter_fcntl`, `sys_enter_ioctl`, `sys_enter_dup3`, `sys_enter_pipe2`,
`sys_enter_epoll_ctl`, `sys_enter_epoll_pwait2`,
`sys_enter_inotify_add_watch`, `sys_enter_fanotify_mark`, `sys_enter_poll`,
`sys_enter_ppoll`, `sys_enter_select`, and `sys_enter_pselect6`.
File data-movement fallbacks expose aliases for common entry tracepoints such
as `sys_enter_pread64`, `sys_enter_pwrite64`, `sys_enter_readv`,
`sys_enter_writev`, `sys_enter_preadv2`, `sys_enter_sendfile`,
`sys_enter_copy_file_range`, `sys_enter_splice`, `sys_enter_tee`, and
`sys_enter_vmsplice`, plus Linux 6.5+ `sys_enter_cachestat`.
Memory-management fallbacks expose aliases for common entry tracepoints such as
`sys_enter_mmap`, `sys_enter_mprotect`, `sys_enter_mremap`, `sys_enter_mincore`,
`sys_enter_msync`, NUMA memory-policy calls such as `sys_enter_mbind` and
`sys_enter_move_pages`, process-memory calls such as `sys_enter_process_vm_readv`,
Linux 4.9+ pkey calls such as `sys_enter_pkey_mprotect`, and Linux 5.17+
`sys_enter_set_mempolicy_home_node`, plus Linux 6.10+ `sys_enter_mseal`;
swap calls such as `sys_enter_swapon` and `sys_enter_swapoff` are
source-backed as well.
Time and timer fallbacks expose aliases for common entry tracepoints such as
`sys_enter_utime`, `sys_enter_utimes`, `sys_enter_futimesat`,
`sys_enter_utimensat`, `sys_enter_gettimeofday`, `sys_enter_clock_gettime`,
`sys_enter_timer_create`, `sys_enter_timerfd_settime`, and `sys_enter_alarm`.
AIO and io-priority fallbacks expose aliases for entry tracepoints such as
`sys_enter_io_setup`, `sys_enter_io_submit`, `sys_enter_io_getevents`,
Linux 4.18+ `sys_enter_io_pgetevents`, `sys_enter_ioprio_set`, and
`sys_enter_ioprio_get`.
Signal fallbacks expose aliases for common entry tracepoints such as
`sys_enter_kill`, `sys_enter_tgkill`, `sys_enter_rt_sigaction`,
`sys_enter_rt_sigtimedwait`, `sys_enter_signalfd4`, and
`sys_enter_pidfd_send_signal`.
Credential and process-control fallbacks expose source-known aliases for common
entry tracepoints such as `sys_enter_setresuid`, `sys_enter_getresgid`,
`sys_enter_setgroups`, `sys_enter_capset`, `sys_enter_prctl`, and
`sys_enter_getcpu`, plus query-style system calls such as `sys_enter_getrandom`,
`sys_enter_times`, `sys_enter_newuname`, and `sys_enter_sysinfo`, and
process-state calls such as `sys_enter_prlimit64`, `sys_enter_membarrier`,
Linux 4.18+ `sys_enter_rseq`, `sys_enter_set_tid_address`,
`sys_enter_kcmp`, `sys_enter_personality`, `sys_enter_syslog`, and
zero-argument identity calls such as `sys_enter_getpid`.
Instrumentation and security-control fallbacks expose aliases for
`sys_enter_bpf`, `sys_enter_perf_event_open`, `sys_enter_ptrace`,
`sys_enter_seccomp`, `sys_enter_userfaultfd`, and Linux 6.8+ LSM syscalls such
as `sys_enter_lsm_get_self_attr`, `sys_enter_lsm_set_self_attr`, and
`sys_enter_lsm_list_modules`.
Key-management fallbacks expose source-known aliases for entry tracepoints such
as `sys_enter_add_key`, `sys_enter_request_key`, and `sys_enter_keyctl`.
Scheduler fallbacks expose source-known aliases for common entry tracepoints
such as `sys_enter_sched_setscheduler`, `sys_enter_sched_setaffinity`,
`sys_enter_sched_getattr`, `sys_enter_sched_rr_get_interval`, and
`sys_enter_nice`. Futex fallbacks include the legacy `sys_enter_futex` surface,
Linux 5.16+ `sys_enter_futex_waitv`, and Linux 6.7+ `sys_enter_futex_wake`,
`sys_enter_futex_wait`, and `sys_enter_futex_requeue`.
System V IPC fallbacks expose source-known aliases for common message queue,
semaphore, and shared-memory entry tracepoints such as `sys_enter_msgctl`,
`sys_enter_msgrcv`, `sys_enter_semctl`, `sys_enter_semtimedop`,
`sys_enter_shmctl`, and `sys_enter_shmat`.
POSIX message-queue fallbacks expose aliases for entry tracepoints such as
`sys_enter_mq_open`, `sys_enter_mq_timedsend`,
`sys_enter_mq_timedreceive`, `sys_enter_mq_notify`, and
`sys_enter_mq_getsetattr`.
x86-specific syscall fallbacks expose source-known aliases for entry
tracepoints such as Linux 5.0+ `sys_enter_arch_prctl`, legacy
`sys_enter_ioperm`, `sys_enter_iopl`, `sys_enter_modify_ldt`,
`sys_enter_rt_sigreturn`, Linux 6.6+ `sys_enter_map_shadow_stack`, and
Linux 6.14+ `sys_enter_uretprobe`.
When a syscall argument name collides with a preserved tracepoint builtin or
reserved context path such as `pid`, `tgid`, or `arg`, the fallback exposes the
non-conflicting arguments and the raw payload remains available through
`ctx.args`.
syscall-entry pointer fields are modeled as userspace pointers, so
`ctx.filename | read-str --max-len 64` is the preferred form. The generic
fallback `($ctx.args | get 1)` is only a raw numeric ABI value and is not enough
pointer provenance for `read-str`. `ebpf spec` reports tracepoint field
provenance for both paths; fallback syscall fields also report source-backed
minimum kernels for the fallback layout and syscall-specific aliases, while
tracefs-derived fields stay unversioned because they are observed from the local
host.

## Limits

| Resource | Limit |
|----------|-------|
| eBPF stack | 512 bytes |
| String reads | 128 bytes max |
| Map entries | 10,240 per map |
| Ring buffer | 256 KB |
| Stack traces | 127 frames |
