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
| `sk_common` / `sock_common` / `iter_sk_common` | Nullable iterated `sock_common *` pointer from `struct bpf_iter__tcp`. | `iter:tcp` |
| `udp_sk` / `iter_udp_sk` | Nullable iterated `udp_sock *` pointer from `struct bpf_iter__udp`. | `iter:udp` |
| `unix_sk` / `iter_unix_sk` | Nullable iterated `unix_sock *` pointer from `struct bpf_iter__unix`. | `iter:unix` |
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
| `ktime_coarse` | Coarse kernel timestamp (ns) | all runtime-context program types except `freplace`/extension, `syscall`, and `struct_ops` callbacks |
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
| `egress_ifindex` | XDP egress interface index | xdp |
| `user_family` | Userspace-requested socket family | cgroup_sock_addr |
| `user_ip4` | IPv4 destination/source address in host byte order | cgroup_sock_addr (*4 hooks) |
| `user_ip6` | IPv6 address as four host-order `u32` words | cgroup_sock_addr (*6 hooks) |
| `user_port` | Requested port in host byte order | cgroup_sock_addr (*4/*6 hooks) |
| `family` | Kernel socket family | cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `sock_type` | Socket type | cgroup_sock, cgroup_sock_addr |
| `protocol` | Socket protocol on socket contexts; skb protocol / ethertype on skb-backed packet contexts; IP protocol on sk_reuseport | socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_reuseport, sk_skb, sk_skb_parser |
| `bound_dev_if` | Bound device ifindex | cgroup_sock (sock_create, sock_release) |
| `mark` | Socket or skb mark | cgroup_sock (sock_create, sock_release), socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb |
| `priority` | Socket or skb priority | cgroup_sock (sock_create, sock_release), socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser |
| `state` | Current socket or TCP state | cgroup_sock, sock_ops |
| `op` | sock_ops callback opcode | sock_ops |
| `args` | sock_ops callback argument words as four host-order `u32` values | sock_ops |
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
| `sk` | Typed `bpf_sock *` pointer for socket projection such as `$ctx.sk.family` or `$ctx.sk.bound_dev_if`; currently exposes `bound_dev_if`, `family`, `type`, `protocol`, `mark`, `priority`, `src_ip4`, `src_ip6`, `src_port`, `dst_port` (raw network byte order), `dst_ip4`, `dst_ip6`, `state`, `rx_queue_mapping`, plus `cgroup_id` and `ancestor_cgroup_id.N` (`cgroup_skb` only). On program types where the corresponding helpers are valid, `$ctx.sk.tcp.<field>` exposes null-safe TCP metrics from `struct bpf_tcp_sock`, while `$ctx.sk.full.<field>` and `$ctx.sk.listener.<field>` expose fields from `bpf_sk_fullsock` / `bpf_get_listener_sock`; these projections also work after binding `$ctx.sk` to a local and return `0` when there is no socket or the helper returns null | socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, sock_ops |
| `flow_keys` | Typed `bpf_flow_keys *` pointer for flow-dissector projection such as `$ctx.flow_keys.nhoff`, `$ctx.flow_keys.thoff`, `$ctx.flow_keys.addr_proto`, `$ctx.flow_keys.ip_proto`, `$ctx.flow_keys.sport`, `$ctx.flow_keys.dport`, `$ctx.flow_keys.ipv4_src`, `$ctx.flow_keys.ipv4_dst`, `$ctx.flow_keys.ipv6_src.0`, `$ctx.flow_keys.ipv6_dst.3`, `$ctx.flow_keys.flags`, or `$ctx.flow_keys.flow_label` | flow_dissector |
| `nf_state` | Typed `nf_hook_state *` pointer for netfilter projection such as `$ctx.nf_state.hook`, `$ctx.nf_state.pf`, `$ctx.nf_state.in.ifindex`, or `$ctx.nf_state.out.ifindex`; `ctx.state` is also accepted as a netfilter-specific alias | netfilter |
| `skb` | Typed `sk_buff *` pointer for netfilter projection such as `$ctx.skb.len` | netfilter |
| `hook` | Netfilter hook number from `nf_hook_state.hook` | netfilter |
| `pf` / `protocol_family` | Netfilter protocol family from `nf_hook_state.pf` | netfilter |
| `bind_inany` | sk_reuseport bind-in-any state | sk_reuseport |
| `migrating_sk` | Typed migrating `bpf_sock *` pointer on sk_reuseport migration programs | sk_reuseport |
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
| `arg_count` | Number of argument registers available to a BTF-backed tracing program (`bpf_get_func_arg_cnt`) | fentry, fexit, fmod_ret, tp_btf, lsm, lsm_cgroup |
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
they are compile/dry-run only until the loader has a safe multi-uprobe
attach path.

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
`$ctx.unix_sk` / `$ctx.uid` on `iter:unix`.
Socket map iterators expose `$ctx.sk` / `$ctx.iter_sock` for their `sock *`
payload. Other simple single-pointer iterator contexts expose their
kernel-native roots: `$ctx.dmabuf`, `$ctx.rt`, `$ctx.kmem_cache`, `$ctx.ksym`,
and `$ctx.netlink_sk` for `iter:dmabuf`, `iter:ipv6_route`,
`iter:kmem_cache`, `iter:ksym`, and `iter:netlink`, respectively.
`$ctx.current_task` and `$ctx.current_cgroup` remain reserved for helper-backed
current-task semantics on task-aware tracing families. Iterator seq-file output
helpers are modeled for explicit escape-hatch use: `helper-call "bpf_seq_write"
SEQ DATA LEN`, `helper-call "bpf_seq_printf" SEQ FMT FMT_SIZE DATA DATA_LEN`,
and `helper-call "bpf_seq_printf_btf" SEQ BTF_PTR 16 FLAGS` are iter-only,
require a kernel `seq_file *` argument, and require stack/map-backed buffers.
`bpf_seq_printf` may use `0` for `DATA` only when `DATA_LEN` is also `0`.
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
against `ctx.data` rather than `ctx.data_end`. `tc_action`, `tc`, `tcx`, and `netkit` also expose
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
with the ambient skb context pointer materialized automatically. After XDP adjust helpers, previously
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
`bpf_skb_vlan_pop`, `bpf_skb_adjust_room`, and `bpf_set_hash`.
`bpf_skb_store_bytes` flags may contain only `BPF_F_RECOMPUTE_CSUM` and
`BPF_F_INVALIDATE_HASH`.
These skb mutation helpers invalidate guarded
direct packet-pointer facts when the kernel helper contract says the
underlying packet buffer may change. Raw packet-copy helpers are modeled too:
`bpf_skb_load_bytes` works on `flow_dissector`, `socket_filter`, `lwt_*`,
`tc`, `tcx`, `netkit`, `cgroup_skb`, `sk_reuseport`, `sk_skb`, and `sk_skb_parser`;
`bpf_skb_load_bytes_relative` works on `socket_filter`, `tc`, `tcx`, `netkit`, `cgroup_skb`,
and `sk_reuseport`, with `start_header` limited to `BPF_HDR_START_MAC` or
`BPF_HDR_START_NET`; and `bpf_xdp_get_buff_len`, `bpf_xdp_load_bytes`, and
`bpf_xdp_store_bytes` are XDP-only. XDP targets default to SKB/generic
attach mode for safer development attaches; use `xdp:IFACE:drv` or
`xdp:IFACE:hw` when driver or hardware mode is intentional. Append
`:frags`, for example `xdp:IFACE:drv:frags`, when the program needs the
kernel `xdp.frags` section for multi-buffer packets. XDP, TC, TCX, Netkit, and LWT also
model `bpf_csum_diff`; its `from_size` and `to_size` arguments must be
multiples of four, and a null `from` or `to` buffer is accepted only
when the paired size is zero. `ctx.xdp_buff_len` exposes
`bpf_xdp_get_buff_len` directly for XDP programs that need total
multi-buffer packet size rather than the linear `ctx.packet_len`. XDP,
tc_action, TC, TCX, and Netkit also model `helper-call "bpf_check_mtu" $ctx IFINDEX MTU_LEN_PTR LEN_DIFF FLAGS`;
`MTU_LEN_PTR` must be a stack/map-backed `u32` pointer, and XDP requires
`FLAGS = 0`. TC/TCX flag combinations that depend on runtime `mtu_len` /
`len_diff` values remain kernel-enforced. XDP, tc_action, TC, TCX, and Netkit also
model `helper-call "bpf_fib_lookup" $ctx PARAMS_PTR PLEN FLAGS`, where
`PARAMS_PTR` must be a stack/map-backed `bpf_fib_lookup` buffer whose
accessible size covers `PLEN`; `FLAGS` may contain only modeled
`BPF_FIB_LOOKUP_*` bits (`0x3f`), while the kernel still enforces minimum
struct size and flag-combination rules. `tc_action`, TC, TCX, Netkit, and `lwt_xmit` model
the skb tunnel metadata helpers:
`helper-call "bpf_skb_get_tunnel_key" $ctx KEY_PTR SIZE FLAGS`,
`helper-call "bpf_skb_set_tunnel_key" $ctx KEY_PTR SIZE FLAGS`,
`helper-call "bpf_skb_get_tunnel_opt" $ctx OPT_PTR SIZE`, and
`helper-call "bpf_skb_set_tunnel_opt" $ctx OPT_PTR SIZE`. `KEY_PTR` and
`OPT_PTR` must be stack/map-backed buffers whose accessible size covers
`SIZE`; `bpf_skb_get_tunnel_key` accepts only `BPF_F_TUNINFO_IPV6` and
`BPF_F_TUNINFO_FLAGS`, while `bpf_skb_set_tunnel_key` accepts only the
kernel's tunnel-key flag bits through `0x1f`. Detailed tunnel-key struct
sizes remain kernel-enforced. `tc_action`, TC, TCX, and Netkit also model
`helper-call "bpf_skb_get_xfrm_state" $ctx INDEX XFRM_STATE_PTR SIZE 0`;
`XFRM_STATE_PTR` must be a stack/map-backed output buffer whose
accessible size covers `SIZE`, and the final reserved flags argument
must be zero.
`tc_action`, Netkit, TC egress, and TCX egress expose skb cgroup/classifier
metadata as ordinary `ctx.cgroup_classid` and `ctx.route_realm` fields; TC action
and TC/TCX egress also expose `ctx.skb_cgroup_id`. LWT programs expose `ctx.cgroup_classid` and
`ctx.route_realm` through the same helper surface. `ctx.skb_ancestor_cgroup_id.N` exposes the
parameterized skb ancestor cgroup helper with a constant numeric
ancestor level. `ctx.csum_level` exposes the checksum-level query form
of `bpf_csum_level` on `lwt_xmit`, tc_action, TC, TCX, Netkit, `sk_skb`, and `sk_skb_parser`
programs; inc/dec/reset remain helper-call operations because they mutate skb metadata.
`ctx.hash_recalc` exposes `bpf_get_hash_recalc` on LWT and the same
tc_action/TC/TCX/Netkit/`sk_skb` surface when a valid skb hash is needed after packet edits. The
skb-backed packet contexts
(`socket_filter`, `tc_action`, `tc`, `tcx`, `netkit`, `cgroup_skb`, `sk_skb`, and `sk_skb_parser`)
also expose `ctx.sk` for typed `bpf_sock` projection such as
`$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, or
`$ctx.sk.mark`; `cgroup_skb` also exposes `$ctx.sk.cgroup_id` and
`$ctx.sk.ancestor_cgroup_id.N` through the socket cgroup helpers,
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
$ctx.tc_index = 5`, or `mut ctx = $ctx; $ctx.tstamp = 123`. Other
skb-backed metadata fields remain read-only on the remaining hooks.
When the timestamp type must also change, `tc_action`, `tc`, `tcx`, and `netkit` model
`helper-call "bpf_skb_set_tstamp" $ctx TSTAMP TSTAMP_TYPE`; the
current kernel UAPI uses `0` for `BPF_SKB_TSTAMP_UNSPEC` and `1` for
`BPF_SKB_TSTAMP_DELIVERY_MONO`, and the compiler rejects other values.
`tc_action`, TC, TCX, Netkit, and `cgroup_skb` also
model `helper-call "bpf_skb_ecn_set_ce" $ctx` for setting IPv4/IPv6 ECN
CE when the packet is ECN-capable. `tc_action`, TC, TCX, and Netkit model
`helper-call "bpf_skb_change_proto" $ctx PROTO 0` and
`helper-call "bpf_skb_change_type" $ctx TYPE`; protocol changes can resize
the skb, so packet pointers must be reloaded and re-guarded afterward.
The initial `socket_filter` surface
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
`"pass"` / `"drop"`, TC / tc_action closures can return strings like `"ok"` /
`"shot"`, and TCX/Netkit closures can return strings like `"next"` / `"pass"` /
`"ok"` / `"drop"` / `"redirect"`. Raw numeric return codes still work. `redirect IFINDEX` is
the preferred first-class surface for `bpf_redirect` on XDP, tc, tcx, and netkit,
and `redirect --flags N IFINDEX` exposes the helper flags argument
directly; XDP still requires `FLAGS = 0`. On `tc:...:ingress`, `tcx:...:ingress`, and netkit,
`redirect --peer IFINDEX` is the preferred first-class surface for
`bpf_redirect_peer` and still requires `FLAGS = 0`. On tc/tcx/netkit,
`redirect --neigh IFINDEX` is the preferred first-class surface for
the default-neighbor form of `bpf_redirect_neigh`, lowering to
`bpf_redirect_neigh(IFINDEX, 0, 0, FLAGS)`; `FLAGS` must also stay
`0`. The raw `helper-call "bpf_redirect*" ...` forms are still
modeled when you need the escape hatch.

On XDP, `adjust-packet --head|--meta|--tail DELTA` is the preferred first-class surface for packet relayout. It selects the corresponding `bpf_xdp_adjust_*` helper, materializes the ambient context pointer automatically, and returns the helper result directly. On `tc`, `tcx`, `netkit`, `sk_skb`, and `sk_skb_parser`, `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` do the same for `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room`; LWT programs also support `adjust-packet --pull LEN`.

On XDP, tc, tcx, and netkit, `redirect IFINDEX` is the preferred first-class surface for packet redirection. `redirect --peer IFINDEX` selects `bpf_redirect_peer` on `tc:...:ingress` or `tcx:...:ingress`, and `redirect --neigh IFINDEX` selects the default-neighbor form of `bpf_redirect_neigh` on tc/tcx/netkit. All three forms return the helper result directly so a closure can end with `redirect ...`.

On XDP, `redirect-map MAP KEY --kind devmap|devmap-hash|cpumap|xskmap` is the preferred first-class surface for `bpf_redirect_map`. It returns the helper result directly, so a closure can end with `redirect-map ...` instead of spelling the helper name through `helper-call`. Its `--flags` value is limited to the two fallback return-code bits plus `BPF_F_BROADCAST` and `BPF_F_EXCLUDE_INGRESS`.

On `sk_msg`, `sk_skb`, and `sk_skb_parser`, `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class surface for the socket redirect helpers. It picks `bpf_msg_redirect_{map,hash}` or `bpf_sk_redirect_{map,hash}` from the current program type, materializes the ambient context pointer automatically, and returns the helper result directly so a closure can end with `redirect-socket ...`. On `sk_reuseport`, `redirect-socket MAP KEY --kind reuseport-sockarray` selects `bpf_sk_select_reuseport` and materializes the `u32` key pointer required by the helper.

On `tc:...:ingress`, `tcx:...:ingress`, and `sk_lookup`, ordinary assignment to `ctx.sk` is the preferred zero-flag surface for `bpf_sk_assign`: `mut ctx = $ctx; $ctx.sk = $sk`, or `$ctx.sk = 0` on `sk_lookup` to clear a previous selection. `assign-socket SK [--flags FLAGS]` remains available when the program needs the helper status or explicit flags. TC/TCX ingress requires zero flags. `sk_lookup` accepts `--replace` and `--no-reuseport` for `BPF_SK_LOOKUP_F_REPLACE` and `BPF_SK_LOOKUP_F_NO_REUSEPORT`.

On `sock_ops`, `$ctx | map-put MAP KEY --kind sockmap|sockhash` is the preferred first-class surface for `bpf_sock_{map,hash}_update`. The pipeline input is the current `sock_ops` context, `KEY` is materialized as the map key pointer, and `--flags` is limited to `BPF_ANY`, `BPF_NOEXIST`, or `BPF_EXIST`.

Local-storage maps use the ordinary map surface: `$ctx.sk | map-get sock_state --kind sk-storage`, `$ctx.task | map-get task_state --kind task-storage --init { hits: 0 }`, `$ctx.cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 }`, `$ctx.arg0.f_inode | map-delete inode_state --kind inode-storage`, `$ctx.current_task | map-contains task_state --kind task-storage`, and `$ctx.current_cgroup | map-contains cgrp_state --kind cgrp-storage` lower to the corresponding `bpf_*_storage_{get,delete}` helpers. `--init VALUE` passes a typed initial value and defaults `--flags` to `1` (`BPF_LOCAL_STORAGE_GET_F_CREATE`); omit it for lookup-only behavior. Storage-get flags are limited to `0` or `BPF_LOCAL_STORAGE_GET_F_CREATE`. `map-contains` performs a lookup-only storage get and compares the returned pointer against null. The raw storage helper spelling still works through `helper-call` for low-level debugging, but `map-get` / `map-contains` / `map-delete` are the preferred resource-oriented forms. The legacy cgroup-attached `bpf_get_local_storage` helper is recognized in the typed raw-helper model with `flags = 0`, but its deprecated cgroup-storage map family is still not materialized; use `--kind cgrp-storage` with the ordinary map surface for new programs.

Tail calls are exposed as ordinary control flow with `tail-call MAP INDEX` or `INDEX | tail-call MAP`. `MAP` is emitted as a BPF `prog_array`; successful tail calls do not return to the current program, while the compiler emits a default `0` return for the kernel miss/limit fallback path. The raw `helper-call "bpf_tail_call"` form remains available for low-level debugging, but `tail-call` is the preferred surface because it lowers through the modeled terminator path.

`perf_event` currently supports software `cpu-clock`, `task-clock`, `context-switches`, `cpu-migrations`, `page-faults`, `minor-faults`, and `major-faults`, plus hardware `cpu-cycles`, `instructions`, `cache-references`, `cache-misses`, `branch-instructions`, `branch-misses`, `bus-cycles`, `stalled-cycles-frontend`, `stalled-cycles-backend`, and `ref-cpu-cycles` through specs like `perf_event:software:cpu-clock` or `perf_event:hardware:cpu-cycles`. Optional selectors `cpu=N`, `pid=N`, `period=N`, and `freq=N` are supported; omitting the sample policy defaults to `period=1000000`, and omitting `cpu=` attaches on all online CPUs. `pid=N` scopes the event to a single process, and it can be combined with `cpu=N` for one-process/one-cpu sampling. The current surface uses ordinary helper-backed fields like `ctx.pid`, `ctx.comm`, `ctx.cpu`, and `ctx.ktime`, plus perf counter snapshots `ctx.perf_counter`, `ctx.perf_enabled`, and `ctx.perf_running` from `bpf_perf_prog_read_value`. It also reuses `ctx.arg0`-`ctx.arg5` as raw sampled pt_regs register slots, and on x86_64 builds it exposes the raw `bpf_perf_event_data` fields `ctx.sample_period` and `ctx.addr`. The `ctx.argN` values here are sampled register snapshots, not named BTF-backed function arguments.

`cgroup_sysctl` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.write`, `ctx.file_pos`, `ctx.sysctl_name` / `ctx.name`, `ctx.sysctl_base_name` / `ctx.base_name`, `ctx.sysctl_current_value` / `ctx.current_value`, and `ctx.sysctl_new_value` / `ctx.new_value`, and closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes. The sysctl name and value fields are stack-backed 256-byte buffers copied with `bpf_sysctl_get_name`, `bpf_sysctl_get_current_value`, or `bpf_sysctl_get_new_value`; use the raw helpers only when the program needs explicit return-code handling or a different buffer size. `ctx.file_pos` is writable through ordinary assignment after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.file_pos = 0`. Assigning a string or binary byte buffer to `ctx.sysctl_new_value` / `ctx.new_value`, for example `mut ctx = $ctx; $ctx.new_value = "1"`, lowers to `bpf_sysctl_set_new_value`; `ctx.write` remains read-only. Modeled sysctl helpers are available through the ordinary helper surface: `bpf_sysctl_get_name`, `bpf_sysctl_get_current_value`, `bpf_sysctl_get_new_value`, and `bpf_sysctl_set_new_value`. The kernel keeps their usual runtime semantics here: `bpf_sysctl_get_new_value` and `bpf_sysctl_set_new_value` return `-EINVAL` on read contexts, and `bpf_sysctl_get_name` flags are restricted to `0` or `BPF_F_SYSCTL_BASE_NAME`.

`cgroup_sock` currently supports `sock_create`, `sock_release`, `post_bind4`, and `post_bind6`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.family`, `ctx.sock_type`, `ctx.protocol`, `ctx.state`, `ctx.rx_queue_mapping`, `ctx.socket_cookie`, `ctx.netns_cookie`, `ctx.remote_ip4`, `ctx.remote_ip6`, and `ctx.remote_port` on every supported hook. Direct `ctx.bound_dev_if`, `ctx.mark`, and `ctx.priority` are only available on `sock_create` / `sock_release`, matching the current upstream verifier surface more closely, and ordinary assignment is supported there after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.mark = 7`. Direct `ctx.local_ip4` is available on `post_bind4`, `ctx.local_ip6` on `post_bind6`, and `ctx.local_port` on both post-bind hooks. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. On `cgroup_sock`, the source-side projection members follow the same attach-sensitive policy as the direct locals: `$ctx.sk.src_ip4` is only available on `post_bind4`, `$ctx.sk.src_ip6` on `post_bind6`, and `$ctx.sk.src_port` on both post-bind hooks. Destination-side projections such as `$ctx.sk.dst_port` remain available on every hook.

`cgroup_device` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.access_type`, `ctx.device_access`, `ctx.device_type`, `ctx.major`, and `ctx.minor`, and closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes. `ctx.access_type` is the raw kernel encoding `(BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*`; `ctx.device_access` exposes the access flags and `ctx.device_type` exposes the block/char device kind.

`lirc_mode2` attaches to a lirc device path such as `/dev/lirc0`. It exposes `ctx.sample` / `ctx.raw` for the raw 32-bit mode2 sample word, `ctx.value` for the low 24-bit payload, and `ctx.mode` for the high-byte event kind mask. It uses raw integer return codes; simple observation programs can return `0`.

`sock_ops` currently attaches to a cgroup path such as `/sys/fs/cgroup`. It exposes the sock_ops callback opcode and argument words (`ctx.op`, `ctx.args`), the socket tuple and metadata fields (`ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, `ctx.socket_cookie`, `ctx.netns_cookie`), the TCP/congestion and progress counters (`ctx.is_fullsock`, `ctx.snd_cwnd`, `ctx.srtt_us`, `ctx.cb_flags`, `ctx.state`, `ctx.rtt_min`, `ctx.snd_ssthresh`, `ctx.rcv_nxt`, `ctx.snd_nxt`, `ctx.snd_una`, `ctx.mss_cache`, `ctx.ecn_flags`, `ctx.rate_delivered`, `ctx.rate_interval_us`, `ctx.packets_out`, `ctx.retrans_out`, `ctx.total_retrans`, `ctx.segs_in`, `ctx.data_segs_in`, `ctx.segs_out`, `ctx.data_segs_out`, `ctx.lost_out`, `ctx.sacked_out`, `ctx.sk_txhash`, `ctx.bytes_received`, and `ctx.bytes_acked`), plus packet-metadata fields `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.skb_len`, `ctx.skb_tcp_flags`, and `ctx.skb_hwtstamp` when the callback context has packet data available. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and remote port fields are normalized to host byte order. The IPv6 fields are exposed as fixed arrays of four host-order `u32` words, so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `ctx.reply`, `ctx.replylong.<0-3>`, `ctx.cb_flags`, and `ctx.sk_txhash` are writable `u32` words and can be assigned with ordinary Nushell cell-path updates after shadowing the immutable closure parameter as mutable, for example `mut ctx = $ctx; $ctx.reply = 1`, `mut ctx = $ctx; $ctx.replylong.0 = 7`, `mut ctx = $ctx; $ctx.cb_flags = 1`, or `mut ctx = $ctx; $ctx.sk_txhash = 7`. `ctx.cb_flags = ...` lowers through `bpf_sock_ops_cb_flags_set`; the other writable fields are direct context stores. Packet-aware callbacks use the same guarded packet-access model as XDP and tc, and the verifier now requires a proven packet-aware `ctx.op` branch before loading those packet fields. Modeled sock_ops helpers are also available through the ordinary helper surface, including `bpf_getsockopt`, `bpf_setsockopt`, `bpf_load_hdr_opt`, `bpf_store_hdr_opt`, and `bpf_reserve_hdr_opt`. The sock_ops kfunc escape hatch is intentionally narrow; currently `kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0` is modeled for timestamp-sendmsg callbacks, with callback and flag details still enforced by the kernel. Those helpers still follow the kernel's ordinary callback-sensitive runtime rules, so unsupported `ctx.op` combinations can return `-EPERM`; the finer flag-sensitive `bpf_load_hdr_opt` subcases still remain kernel-enforced. sock_ops uses raw integer return codes; observation-only examples should return `1`.

`cgroup_sockopt` currently attaches to `get` and `set` cgroup socket-option hooks such as `/sys/fs/cgroup:get` or `/sys/fs/cgroup:set`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.level`, `ctx.optname`, `ctx.optlen`, `ctx.optval`, `ctx.optval_end`, `ctx.netns_cookie`, and `ctx.sockopt_retval` / `ctx.retval` on `get` hooks, plus a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. `optval` / `optval_end` are surfaced as kernel pointers, so ordinary pointer reads like `($ctx.optval | get 0)` or `read-kernel-str` can inspect the buffer. Ordinary assignment now also covers the writable scalar surfaces the kernel exposes here: `ctx.sockopt_retval` / `ctx.retval` on `cgroup_sockopt:get`, `ctx.level` / `ctx.optname` on `cgroup_sockopt:set`, `ctx.optlen` on either hook, and fixed-index sockopt-buffer rewrites such as `mut ctx = $ctx; $ctx.optval.0 = 1`. Modeled socket-option helpers are also available through the ordinary helper surface here, including `bpf_getsockopt` and `bpf_setsockopt` on the current sockopt context. Closures can return `"allow"` / `"deny"` instead of raw `1` / `0` result codes.

`cgroup_sock_addr` currently exposes `ctx.cpu`, `ctx.ktime`, `ctx.socket_cookie`, `ctx.netns_cookie`, `ctx.user_family`, `ctx.family`, `ctx.sock_type`, and `ctx.protocol` on every modeled hook. IPv4/IPv6 hooks additionally expose `ctx.user_ip4`, `ctx.user_ip6`, and `ctx.user_port`, plus `ctx.msg_src_ip4` on `sendmsg4` and `ctx.msg_src_ip6` on `sendmsg6`. It also normalizes the attach-sensitive IPv4/IPv6 hooks onto the ordinary tuple surface where the kernel semantics are clear: `connect4` / `connect6`, `getpeername4` / `getpeername6`, `sendmsg4` / `sendmsg6`, and `recvmsg4` / `recvmsg6` expose `ctx.remote_ip4`, `ctx.remote_ip6`, and `ctx.remote_port`; `bind4` / `bind6` and `getsockname4` / `getsockname6` expose `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`; and `sendmsg4` / `sendmsg6` additionally expose `ctx.local_ip4` / `ctx.local_ip6` over the source-address fields. `sendmsg4` / `sendmsg6` still do not expose `ctx.local_port`, because the kernel surface does not provide a corresponding source-port field there. These mutable kernel fields can be assigned through the same aliases after shadowing the closure parameter as mutable, for example `mut ctx = $ctx; $ctx.remote_ip4 = 0x7f000001` on `connect4` / `getpeername4` / `sendmsg4` / `recvmsg4`, `$ctx.local_port = 8080` on `bind4` / `bind6` / `getsockname4` / `getsockname6`, or `$ctx.local_ip6.0 = 0` on `bind6` / `getsockname6` / `sendmsg6`. The UNIX hooks `connect_unix`, `sendmsg_unix`, `recvmsg_unix`, `getpeername_unix`, and `getsockname_unix` emit the matching libbpf `cgroup/*_unix` sections for compile/dry-run, but live attach is rejected until Aya exposes the `BPF_CGROUP_UNIX_*` attach types or the loader grows an equivalent lower-level attach path. Their direct read surface is intentionally limited to common socket metadata, while path mutation is available as ordinary assignment on UNIX hooks: `mut ctx = $ctx; $ctx.sun_path = "/tmp/demo.sock"` lowers to `bpf_sock_addr_set_sun_path`. It also exposes a typed `ctx.sk` pointer for ordinary socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. The IPv4 address and port fields are normalized to host byte order. The IPv6 fields are exposed as fixed arrays of four host-order `u32` words, so ordinary Nushell indexing works, for example `($ctx.user_ip6 | get 3)`. `cgroup_sock_addr` closures can return `"allow"` / `"deny"` instead of raw `1` / `0` codes. Modeled socket helpers are also available through the ordinary helper surface: `bpf_bind` on inet `connect4` / `connect6` hooks, `bpf_getsockopt` / `bpf_setsockopt` across `cgroup_sock_addr` hooks including UNIX hooks, and `bpf_sock_addr_set_sun_path` behind `ctx.sun_path` assignment on UNIX hooks. Numeric result codes still work too.

`sk_lookup` currently attaches to a network-namespace path such as `/proc/self/ns/net`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.family`, `ctx.protocol`, `ctx.cookie`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, `ctx.local_port`, `ctx.ingress_ifindex`, and a typed `ctx.sk` pointer for socket projection such as `$ctx.sk.bound_dev_if`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, `$ctx.sk.state`, or `$ctx.sk.mark`. `mut ctx = $ctx; $ctx.sk = $sk` selects a socket through `bpf_sk_assign` with zero flags, and `$ctx.sk = 0` clears an earlier selection. `assign-socket $sk --replace` / `assign-socket 0 --replace` remain available when explicit sk_lookup flags are needed. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `sk_lookup` closures can return `"pass"` / `"drop"` instead of raw `1` / `0` result codes; `"allow"` / `"deny"` aliases also work.

`sk_reuseport` currently has compile/dry-run support for `sk_reuseport:select` and `sk_reuseport:migrate`. It emits `sk_reuseport` or `sk_reuseport/migrate` sections and exposes the `sk_reuseport_md` packet surface: `ctx.packet_len` / `ctx.len`, `ctx.data`, `ctx.data_end`, `ctx.eth_protocol`, `ctx.ip_protocol` / `ctx.protocol`, `ctx.hash`, `ctx.socket_cookie`, and `ctx.bind_inany`. It also exposes the selected `ctx.sk` socket pointer as non-null and the migrating `ctx.migrating_sk` pointer as nullable for ordinary socket projections such as `$ctx.sk.bound_dev_if` or `$ctx.migrating_sk.state`. `redirect-socket MAP KEY --kind reuseport-sockarray` is the first-class socket-selection surface and lowers to `bpf_sk_select_reuseport`. Live attach is intentionally rejected before Aya load until the loader has a safe reuseport attach implementation.

`raw_tracepoint.w` / `raw_tp.w` currently has compile/dry-run support for writable raw tracepoint targets such as `raw_tracepoint.w:sys_enter`. It emits a `raw_tracepoint.w/<name>` section and reuses the ordinary raw tracepoint positional argument surface (`ctx.arg0`, `ctx.arg1`, ...). Live attach is intentionally rejected before Aya load because the current loader does not preserve writable raw-tracepoint sections, and rewriting them as ordinary raw tracepoints would change verifier semantics.

`flow_dissector` currently has compile/dry-run support for network-namespace targets such as `flow_dissector:/proc/self/ns/net`. It emits a `flow_dissector` section and exposes the kernel's narrow `__sk_buff` flow-dissector surface: `ctx.data`, `ctx.data_end`, and `ctx.flow_keys` projections including `nhoff`, `thoff`, `addr_proto`, `is_frag`, `is_first_frag`, `is_encap`, `ip_proto`, `n_proto`, `sport`, `dport`, `ipv4_src`, `ipv4_dst`, fixed-array `ipv6_src` / `ipv6_dst` words, `flags`, and `flow_label`. Length and protocol decisions should come from guarded packet reads or the dissected flow keys rather than direct `ctx.packet_len` / `ctx.protocol` fields. Return aliases are `"ok"` / `"parsed"` for `0`, `"drop"` for `2`, and `"continue"` / `"fallback"` for `129`. Live attach is intentionally rejected before Aya load because this loader does not yet implement safe flow-dissector attachment and Aya does not expose a high-level attach wrapper for this section.

`netfilter` currently has compile/dry-run support for targets such as `netfilter:ipv4:pre_routing[:priority=N][:defrag]`. It emits a `netfilter` section and exposes the safe scalar `bpf_nf_ctx.state` fields `ctx.hook` and `ctx.pf` / `ctx.protocol_family`, plus the verifier-provided trusted pointers `ctx.state` / `ctx.nf_state` (`nf_hook_state *`) and `ctx.skb` (`sk_buff *`) for ordinary typed projections such as `ctx.state.in.ifindex` or `ctx.skb.len`. Pointer-valued hops from those trusted netfilter roots stay as direct trusted-BTF loads, while scalar leaves continue to use safe kernel reads. BPF-link specs accept `ipv4` / `ipv6` families and `pre_routing`, `local_in`, `forward`, `local_out`, or `post_routing` hooks; `defrag` requires priority greater than `-400`. Return aliases are `"drop"` / `"deny"` for `0`, `"accept"` / `"allow"` / `"pass"` / `"ok"` for `1`, `"stolen"` for `2`, `"queue"` for `3`, and `"repeat"` for `4`. Live attach is intentionally rejected before Aya load until the loader has BPF-link netfilter attach support.

`lwt_in`, `lwt_out`, `lwt_xmit`, and `lwt_seg6local` currently have compile/dry-run support for descriptive targets such as `lwt_xmit:demo-route`. They emit their matching `lwt_*` sections and expose a conservative `__sk_buff` packet surface: `ctx.packet_len` / `ctx.len`, `ctx.data`, `ctx.data_end`, `ctx.eth_protocol` / `ctx.protocol`, `ctx.ingress_ifindex`, `ctx.ifindex`, `ctx.hash`, `ctx.hash_recalc`, `ctx.cgroup_classid`, `ctx.route_realm`, `ctx.mark`, `ctx.priority`, and fixed `ctx.cb.N`. Kernel-rejected LWT skb fields such as `ctx.tc_classid`, `ctx.wire_len`, `ctx.tstamp`, `ctx.tstamp_type`, and `ctx.hwtstamp` are intentionally not exposed. `adjust-packet --pull LEN` is available across LWT programs for packet linearization. `lwt_in` and `lwt_xmit` model `helper-call "bpf_lwt_push_encap" $ctx TYPE HDR_PTR LEN`; `HDR_PTR` must be a stack/map-backed header buffer whose accessible size covers `LEN`, while program/type compatibility is still kernel-enforced. `lwt_xmit` additionally supports direct `ctx.data.*` packet stores, `redirect IFINDEX`, `adjust-packet --head|--tail DELTA`, `ctx.csum_level`, skb tunnel metadata helpers, and the modeled skb packet-edit helper surface also available to `tc_action` / tc / `sk_skb` (`bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_csum_update`, and `bpf_set_hash_invalid`). `lwt_seg6local` models `bpf_lwt_seg6_store_bytes`, `bpf_lwt_seg6_adjust_srh`, and `bpf_lwt_seg6_action`; the buffer-taking forms require stack/map-backed buffers sized by their `LEN` / `PARAM_LEN` arguments. All of these LWT mutating helpers can invalidate packet pointers, so reload and re-guard `ctx.data` / `ctx.data_end` afterward. Return aliases are `"ok"` / `"pass"` for `0`, `"drop"` for `2`, and `"redirect"` for `7`; `lwt_in` and `lwt_xmit` also accept `"reroute"` for `128`. Live attach is intentionally rejected before Aya load because this loader does not yet implement route LWT attachment and Aya does not parse these sections.

`sk_msg` currently attaches to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.packet_len` / `ctx.len` / `ctx.size`, `ctx.data`, `ctx.data_end`, `ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`, plus a typed `ctx.sk` pointer for socket projection such as `$ctx.sk.family`, `$ctx.sk.src_port`, `$ctx.sk.dst_port`, or `$ctx.sk.priority`. `ctx.data` / `ctx.data_end` use the same guarded packet access model as XDP and tc, so ordinary byte/scalar reads like `($ctx.data | get 0)` work, and direct scalar/header stores through `ctx.data.*` use the same guarded packet-store lowering as other writable packet contexts. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. `sk_msg` uses raw integer verdict codes; closures can return `"pass"` / `"drop"` instead of raw `1` / `0`, and `"allow"` / `"deny"` aliases also work. `adjust-message --apply BYTES`, `adjust-message --cork BYTES`, `adjust-message --pull START END [--flags N]`, `adjust-message --push START LEN [--flags N]`, and `adjust-message --pop START LEN [--flags N]` are the preferred first-class message-byte surfaces here because they select the corresponding `bpf_msg_*` helper automatically from the current program type. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_msg_redirect_map` or `bpf_msg_redirect_hash` automatically from the current program type. `adjust-message --pull` can invalidate previously loaded `ctx.data` / `ctx.data_end` pointers, so reload them after the helper before reading packet bytes again. Socket helper-backed projections are available through ordinary `ctx.sk.full.<field>`, `ctx.sk.listener.<field>`, and `ctx.sk.tcp.<field>` paths when the corresponding helper is valid.

`bpf_msg_pull_data` reserves its flags argument for future use, so `adjust-message --pull ... --flags N` and raw `helper-call "bpf_msg_pull_data" ...` require `N = 0`.

`sk_skb` currently emits `sk_skb/stream_verdict` programs attached to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It exposes `ctx.cpu`, `ctx.ktime`, `ctx.packet_len`, `ctx.data`, `ctx.data_end`, `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.napi_id`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.ingress_ifindex`, `ctx.ifindex`, `ctx.tc_index`, `ctx.hash`, `ctx.priority`, `ctx.family`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port` through the existing skb-backed packet model, so ordinary guarded packet reads like `($ctx.data | get 0)` work. The IPv4 address and remote port fields are normalized to host byte order, and the IPv6 fields are exposed as fixed arrays of four host-order `u32` words so ordinary Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`. This initial slice uses verdict-style return codes with `pass` / `drop` aliases. `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` are the preferred first-class skb relayout surfaces here because they select `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room` automatically from the current program type. Modeled skb packet-edit helpers are also available through the ordinary helper surface, including `bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_get_hash_recalc`, `bpf_csum_update`, and `bpf_set_hash_invalid`. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_sk_redirect_map` or `bpf_sk_redirect_hash` automatically from the current program type. Reload `ctx.data` and `ctx.data_end` after `adjust-packet --head`, `adjust-packet --tail`, `adjust-packet --pull`, or `adjust-packet --room` before reading packet bytes again.

`sk_skb_parser` currently emits `sk_skb/stream_parser` programs attached to a pinned sockmap or sockhash path such as `/sys/fs/bpf/demo_sockmap`. It uses the same skb-backed packet context as `sk_skb`, including `ctx.family`, `ctx.pkt_type`, `ctx.queue_mapping`, `ctx.eth_protocol`, `ctx.vlan_present`, `ctx.vlan_tci`, `ctx.vlan_proto`, `ctx.cb`, `ctx.napi_id`, `ctx.gso_segs`, `ctx.gso_size`, `ctx.ifindex`, `ctx.tc_index`, `ctx.hash`, `ctx.priority`, `ctx.remote_ip4`, `ctx.remote_ip6`, `ctx.remote_port`, `ctx.local_ip4`, `ctx.local_ip6`, and `ctx.local_port`, with the same host-order normalization rules for IPv4 addresses, remote ports, and IPv6 word arrays. Its return contract is a raw integer parser result rather than a verdict alias surface, so ordinary examples should return `0` or another integer length. `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` are the preferred first-class skb relayout surfaces here because they select `bpf_skb_change_{head,tail}`, `bpf_skb_pull_data`, and `bpf_skb_adjust_room` automatically from the current program type. Modeled skb packet-edit helpers are also available through the ordinary helper surface, including `bpf_skb_store_bytes`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_get_hash_recalc`, `bpf_csum_update`, and `bpf_set_hash_invalid`. `redirect-socket MAP KEY --kind sockmap|sockhash` is the preferred first-class redirect surface here because it selects `bpf_sk_redirect_map` or `bpf_sk_redirect_hash` automatically from the current program type. Reload `ctx.data` and `ctx.data_end` after `adjust-packet --head`, `adjust-packet --tail`, `adjust-packet --pull`, or `adjust-packet --room` before reading packet bytes again.

`kprobe`, `kprobe.multi`, `ksyscall`, `uprobe`, and `uprobe.multi` expose `ctx.arg0`-`ctx.arg5` through `pt_regs`; `kretprobe`, `kretprobe.multi`, `kretsyscall`, `uretprobe`, and `uretprobe.multi` expose `ctx.retval` through `pt_regs`. `raw_tracepoint` and `raw_tracepoint.w` expose raw positional `ctx.argN` slots. `fentry`, `fexit`, `fmod_ret`, `tp_btf`, `lsm`, `lsm_cgroup`, and `struct_ops` callbacks resolve arguments from kernel BTF; those kernel-BTF-backed contexts also expose named aliases through `ctx.arg.<name>` when names are available, and `fexit` / `fmod_ret` additionally expose `ctx.retval`.
`kprobe.multi` emits `kprobe.multi/PATTERN` sections and `kretprobe.multi` emits `kretprobe.multi/PATTERN` sections; live attach resolves the wildcard against `/proc/kallsyms` and attaches ordinary kprobe/kretprobe links to each match, rejecting overly broad patterns above the loader's safety cap. `uprobe.multi` emits `uprobe.multi/PATH:PATTERN` sections and `uretprobe.multi` emits `uretprobe.multi/PATH:PATTERN` sections; live attach resolves the wildcard against the target ELF's function symbols and attaches ordinary uprobe/uretprobe links to each match, also rejecting overly broad patterns above the loader's safety cap. `ksyscall` emits `ksyscall/SYSCALL` sections and `kretsyscall` emits `kretsyscall/SYSCALL` sections; live attach resolves the syscall name against `/proc/kallsyms` and attaches to every matching ABI wrapper on the host. `lsm_cgroup` emits `lsm_cgroup/HOOK` sections and is compile/dry-run only until the loader can safely handle cgroup LSM attachment. `uprobe.s` and `uretprobe.s` emit sleepable user-probe sections with the same context surface as ordinary uprobes. `fmod_ret` emits `fmod_ret/FUNC` or `fmod_ret.s/FUNC` sections and is compile/dry-run only until the loader can safely handle modify-return attachment.
Scalar and pointer trampoline values work directly. By-value trampoline args and pointer-backed trampoline args/returns can project scalar/pointer fields such as `ctx.arg0.some_field` and can cross intermediate and repeated pointer hops such as `ctx.arg0.foo.bar` or `ctx.arg0.fdt.fd.f_inode.i_ino`. Scalar leaves from pointer-backed kernel/user projections are lowered through null-guarded `bpf_probe_read_{kernel,user}`; pointer-valued hops from non-user BTF trampoline roots stay as direct trusted-BTF kernel pointer loads, so owner pointers such as `ctx.arg0.f_inode` can feed typed local-storage helpers without losing verifier provenance. Fixed-size arrays can also be indexed with numeric path segments like `ctx.arg0.comm.0`, and pointer-backed sequences can now also be indexed with constant numeric segments such as `ctx.arg0.fdt.fd.0.f_inode.i_ino` or `let fd = $ctx.arg0.fdt.fd; $fd.0.f_inode.i_ino`. The same typed pointer traversal also works through numeric `get`, for example `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`.
Stack-backed fixed arrays support the same runtime indexing, for example `let idx = ($ctx.pid mod 2); ($ctx.arg0.comm | get $idx)`. Bounded `for` loops over static integer ranges also lower to verifier-safe loops, so `for i in 0..0 { ... get $i ... }` now works, explicit negative-step descending ranges lower too, and bounded arithmetic on those indices such as `let j = (($i + 1) mod 2)` is preserved. The same range tracking now works for typed unsigned runtime fields such as `let idx = ($ctx.arg0.fdt.max_fds mod 2)`. Branch-sensitive narrowing also works for both bound and repeated direct paths, for example `let max = $ctx.arg0.fdt.max_fds; if $max > 0 { let idx = ($max - 1); ... }` or `if $ctx.arg0.fdt.max_fds > 0 { let idx = ($ctx.arg0.fdt.max_fds - 1); ... }`. Typed BTF bitfields can also be projected through the same paths, including after numeric `get`, for example `let idx = ($ctx.pid mod 2); let clamp = ($ctx.arg0.uclamp_req | get $idx); $clamp.value`.
Terminal array leaves and unsupported aggregate leaves are exposed as stack-backed byte buffers, while representable terminal struct leaves keep their field layouts, including BTF bitfield members, for `count` / `ebpf counters`, and single-value `emit` can stream those struct leaves as records. Nested array/record fields inside emitted values also decode recursively when the compiler can preserve their layouts. `emit` still preserves unsupported aggregate layouts as binary payloads, and `count` supports them as byte-buffer keys. `ebpf counters` decodes those keys using any schema the compiler still has: arrays and typed structs can surface as strings, lists, or records, while opaque aggregate layouts still display as `binary`.
Plain trampoline `ctx.argN` / `ctx.retval` loads also preserve their typed pointer or aggregate layouts across bindings, so `let files = $ctx.arg0; $files.fdt.fd.f_inode.i_ino`, `ctx.arg0.fdt.fd.0.f_inode.i_ino`, `let fd = $ctx.arg0.fdt.fd; $fd.0.f_inode.i_ino`, `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`, and `let inode = $ctx.arg0.f_inode; $inode.i_sb.s_flags` continue to type-check and lower as expected. Named parameter access works through the same typed lowering path, for example `ctx.arg.prev_cpu`, `ctx.arg.p.pid`, `ctx.arg.file.f_flags`, or `ctx.arg.file.f_inode.i_ino`. 16-byte byte-array/string keys such as `ctx.arg0.comm` continue to display as strings. Aggregate `fexit` / `fmod_ret` returns still depend on kernel trampoline support; some kernels reject struct returns entirely.

Generic named maps are also available through `map-get`, `map-put`, `map-delete`, `map-push`, `map-peek`, and `map-pop`. `map-get`, `map-peek`, and `map-pop` return maybe-null pointers. When a prior typed `map-put` established the value layout in the same closure, projections like `let entry = ($ctx.pid | map-get seen_paths --kind hash); if $entry != 0 { $entry.dentry.d_flags }` lower through that preserved map-value schema, and whole-value uses like `{ $entry | emit }` or `{ $entry | count }` preserve the same typed aggregate layout instead of collapsing to a raw pointer scalar. That same typed `map-put` / `map-push` seeding now also accepts metadata-built record values when the record fields already have a truthful fixed layout and tracked semantics, so ordinary record construction can feed typed map flows without an intermediate local materialization step. The preserved layout also survives record construction, so `if $entry != 0 { { path: $entry } | emit }` streams `path` as a nested record instead of a raw pointer or opaque bytes. The same null-checked layout now also survives simple user-defined function boundaries, so `def project-entry [entry] { $entry }` can feed `if $entry != 0 { (project-entry $entry) | emit }` without collapsing back to an untyped scalar. Call-site typed arguments now also specialize simple user-defined functions, so callees can project typed fields directly from their parameters, for example `def inode-flags [file] { $file.f_inode.i_flags }`. Queue/stack maps now preserve their pushed value layouts the same way: a typed `map-push` establishes the layout used by later `map-peek` / `map-pop` in the same closure, and pinned peers attached with the same `--pin` group can reuse that schema too. Socket maps use `map-put` from `sock_ops` for updates and `redirect-socket` from `sk_msg` / `sk_skb` for redirects; reuseport socket arrays use `redirect-socket` from `sk_reuseport` for socket selection. Local-storage `map-get --init` uses the same typed value-schema path for `sk-storage`, `task-storage`, `inode-storage`, and `cgrp-storage` maps. Bloom-filter maps use the same typed `map-push` value layout path, but intentionally do not support first-class `map-peek` because kernel bloom-filter peek treats its value argument as an input membership probe rather than an output buffer. When looked-up aggregates are written back through `map-put`, the stored value shape stays canonical too, so map-to-map copies preserve the real aggregate layout instead of a pointer wrapper. When those maps are attached with the same `--pin` group, active pinned programs now reuse that typed schema across program boundaries too.

Leading annotated `mut` bindings at the top of an attached eBPF closure now lower as compiler-managed per-program globals backed by `.data` or `.bss`, so ordinary Nushell variable syntax can express private state without a helper: `{|ctx| mut state: int = 0; $state = ($state + 1); $state | count }`. The initializer must be a compile-time constant today, and only the leading declaration group at the top of the closure is hoisted this way. That is now the preferred small-state path when plain variable syntax is enough. For supported annotations, the declared Nushell type is now the layout source for that global, so record field order comes from the annotation rather than the record literal initializer. When the annotation itself fully fixes a truthful layout, `null` also works as a zero-initialized `.bss` initializer, for example `{|ctx| mut state: record<pid: int stats: record<hits: int ok: bool>> = null; ... }`. Partial typed record initializers follow the same rule for fixed-layout fields, so `{|ctx| mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 }; ... }` zero-fills `stats` instead of forcing a verbose full literal. That zero-init path is intentionally limited to scalar and nested scalar-record layouts whose size is fixed by the plain Nushell annotation alone; string, binary, and list globals still need an explicit exemplar or the typed named-global path so the compiler knows their real capacity. Keep those annotated `mut` declarations before function definitions and other top-level statements; a typed `mut` that appears later is not treated as a compiler-managed global.

Compiler-managed named globals are still available through `global-define`, `global-get`, and `global-set` when you need an explicit shared name or source-order-independent declaration. Leading typed `mut` bindings remain the preferred private-state path when ordinary variable syntax is enough. These named globals are compiler-managed per-program globals backed by `.data` or `.bss`. `global-define` is declarative: by default a compile-time constant input establishes the fixed layout and initial contents without doing a runtime store, so source order does not matter. `global-define --zero` takes the next step and uses the input only for layout inference, allocating a zero-initialized `.bss` global without a runtime store. If you use `global-define --type`, no exemplar is needed for the layout: with no pipeline input it declares a zero-initialized global directly, and with a compile-time constant input it combines the explicit fixed layout with explicit initial contents. Currently `i8` / `i16` / `i32` / `int` (alias `i64`), `u8` / `u16` / `u32` / `u64`, `bool`, and `bytes:N` are supported as direct typed declarations, and that now also extends to `string:N`, `list:int:N` (alias `list:i64:N`), and fixed arrays such as `array{u32:4}` or `array{record{pid:int,cpu:u32}:2}`, plus nested `record{field:type,...}` declarations whose fields can themselves be scalars, fixed `bytes:N` / `binary:N`, `string:N`, `list:int:N`, `array{type:N}`, or further `record{...}` layouts. Typed initializers are zero-padded within those declared capacities, and typed record initializers may omit fields that should start zeroed, so forms like `"bash" | global-define --type string:16 seen_comm`, `[11 22] | global-define --type 'array{u32:4}' seen_ports`, `[{pid: 7 cpu: 2} {pid: 9 cpu: 3}] | global-define --type 'array{record{pid:int,cpu:u32}:2}' seen_entries`, `{ entries: [{pid: 7 cpu: 2} {pid: 9 cpu: 3}] } | global-define --type 'record{entries:array{record{pid:int,cpu:u32}:2}}' seen_state`, `{ pid: 7, samples: [11 22] } | global-define --type 'record{pid:int,samples:list:int:4}' seen_state`, and `{ pid: 7 } | global-define --type 'record{pid:int,samples:list:int:4}' seen_state` are valid. `global-get` preserves those typed string/list/array field semantics too, so projections like `$state.msg`, `($state.vals | get 1)`, `($ports | get 0)`, `($entries | get 1).cpu`, or `($state.entries | get 1).cpu` behave the same way as the ordinary typed mutable global path. If you skip `global-define`, the first `global-set` for a given name still establishes the fixed layout used by later `global-get` and `global-set` calls in the same closure; when that first write is a compile-time constant the global is initialized from it, otherwise it starts zeroed. That same first-write inference now also works for metadata-built record values, including nested record builders, when every field already has a truthful fixed layout and tracked semantics, so ordinary record construction can seed named globals without an intermediate local materialization step. They are best suited for small per-program state without the overhead of an explicit map. Like the current mutable-capture path, they only support values with a truthful fixed layout.

Generic map `--kind` now supports `hash`, `array`, `queue`, `stack`, `bloom-filter`, `cgroup-array`, `lpm-trie`, `lru-hash`, `per-cpu-hash`, `per-cpu-array`, and `lru-per-cpu-hash`. `queue` and `stack` use `map-push`, `map-peek`, and `map-pop` instead of `map-put` / `map-get`. Lookup-capable generic maps use `map-get` for pointer reads and `map-contains` for boolean membership checks; `map-contains` defaults to `--kind hash` and also accepts `array`, `lpm-trie`, `lru-hash`, `per-cpu-hash`, `per-cpu-array`, and `lru-per-cpu-hash`. `map-put` flags are limited to `BPF_ANY`, `BPF_NOEXIST`, or `BPF_EXIST`; queue/stack `map-push` flags are limited to `0` or `BPF_EXIST`. `bloom-filter` uses first-class `map-push` to insert values and `map-contains --kind bloom-filter` for membership probes. It does not support first-class `map-peek`, `map-pop`, `map-get`, `map-put`, or `map-delete`. Per-cpu maps use the ordinary `map-get` surface for current-CPU/default lookups; explicit CPU reads can use the modeled escape hatch `helper-call "bpf_map_lookup_percpu_elem" MAP KEY_PTR CPU --kind per-cpu-hash|per-cpu-array|lru-per-cpu-hash`, where `KEY_PTR` must already be a stack/map-backed key pointer. Socket map kinds (`sockmap` and `sockhash`) use `map-put` on `sock_ops` programs for updates and `redirect-socket` on message/SKB stream programs for redirects. `reuseport-sockarray` is reserved for `redirect-socket` on `sk_reuseport`, where it emits a `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` map and selects `bpf_sk_select_reuseport`. Local-storage map kinds (`sk-storage`, `task-storage`, `inode-storage`, and `cgrp-storage`) use `map-get` / `map-contains` / `map-delete` over an owning object pointer instead of generic key/value update helpers. Special map families such as `ringbuf`, `perf-event-array`, `stack-trace`, and `prog-array` are selected by their owning surfaces (`emit`, perf-event output helpers, `ctx.kstack` / `ctx.ustack`, and `tail-call`) rather than generic map commands. The compiler also recognizes but intentionally rejects map families that need additional object/loader modeling: `array-of-maps` / `hash-of-maps` require inner-map metadata, `user-ringbuf` requires drain callback support, `arena` requires map-extra and mmap support, `struct-ops` belongs to struct_ops object loading, and deprecated cgroup-storage map types should use `cgrp-storage` instead. Raw ring-buffer helpers enforce the kernel flag contracts too: reserve flags must be `0`, output/submit/discard flags may contain only `BPF_RB_NO_WAKEUP` / `BPF_RB_FORCE_WAKEUP`, and query flags must be one of the kernel `BPF_RB_*` selectors. `cgroup-array` maps use `map-contains --kind cgroup-array` with a cgroup-array slot index; tc_action, tc, tcx, netkit, and lwt_* programs lower to `bpf_skb_under_cgroup(ctx, map, index)` for the current packet, while other programs lower to the base helper `bpf_current_task_under_cgroup(map, index)` for the current task. The raw helper spelling remains available as an escape hatch. `lpm-trie` uses the kernel's raw trie-key layout, so the key bytes must already begin with a `u32` prefix length followed by the trie payload.

The current-task identity helpers are available as ordinary context fields on
tracing-style runtime contexts: `ctx.pid` / `ctx.tid`, `ctx.tgid`,
`ctx.uid`, and `ctx.gid` expose the split halves, while `ctx.pid_tgid` and
`ctx.uid_gid` expose the kernel-packed `u64` helper values directly. The
current-task cgroup ID is available as the ordinary `ctx.cgroup_id` field on
runtime-context programs. Ancestor IDs use a constant numeric cell-path level,
for example `ctx.ancestor_cgroup_id.0`, and return the same scalar ID shape as
`bpf_get_current_cgroup_id`. Extension, syscall, and `struct_ops` callback
specs do not expose this field surface.

`ctx.ktime` remains the preferred ordinary timestamp surface. Specific
kernel clocks/counters are also available as ordinary fields:
`ctx.ktime_boot`, `ctx.ktime_coarse`, `ctx.ktime_tai`, and `ctx.jiffies`.
The corresponding modeled helper escape hatch forms remain available.
Pseudo-randomness is also available without raw helper spelling as either the
ordinary Nushell primitive `random int` or the context fields `ctx.random` /
`ctx.prandom_u32`.

`redirect-map` is the first-class XDP surface for `bpf_redirect_map`. It takes a literal map name plus a key, requires `--kind devmap`, `--kind devmap-hash`, `--kind cpumap`, or `--kind xskmap`, and returns the helper result directly so it can be the closure's final XDP action. `--flags` stays available for the helper's fallback return-code bits when the map lookup misses plus broadcast/exclude-ingress bits.

`adjust-packet` is the first-class packet-relayout surface. On XDP it takes a delta from pipeline input or a positional argument, requires exactly one of `--head`, `--meta`, or `--tail`, and lowers to the corresponding `bpf_xdp_adjust_*` helper while materializing the ambient context pointer automatically. On `tc`, `tcx`, `netkit`, `sk_skb`, and `sk_skb_parser`, `adjust-packet --head|--tail DELTA`, `adjust-packet --pull LEN`, and `adjust-packet --room LEN_DIFF --mode MODE [--flags N]` do the same for the skb relayout helpers.

`adjust-message` is the first-class `sk_msg` byte-window and reshaping surface. `adjust-message --apply BYTES` and `adjust-message --cork BYTES` lower to `bpf_msg_apply_bytes` and `bpf_msg_cork_bytes`. `adjust-message --pull START END [--flags N]`, `adjust-message --push START LEN [--flags N]`, and `adjust-message --pop START LEN [--flags N]` lower to `bpf_msg_pull_data`, `bpf_msg_push_data`, and `bpf_msg_pop_data`; pull flags are reserved and must be `0`. The ambient message context pointer is materialized automatically and the helper result is returned directly.

`redirect` is the first-class packet redirect surface for XDP, tc, tcx, and netkit. It takes an ifindex from pipeline input or a positional argument and returns the helper result directly. Plain `redirect IFINDEX` lowers to `bpf_redirect`. `redirect --peer IFINDEX` lowers to `bpf_redirect_peer` on `tc:...:ingress`, `tcx:...:ingress`, or netkit, and `redirect --neigh IFINDEX` lowers to the default-neighbor `bpf_redirect_neigh(IFINDEX, 0, 0, FLAGS)` form on tc/tcx/netkit. `--flags` stays available for the helper's flags argument.

`redirect-socket` is the first-class socket redirect/selection surface for `sk_msg`, `sk_skb`, `sk_skb_parser`, and `sk_reuseport`. It takes a literal map name plus a key, requires `--kind sockmap` / `--kind sockhash` on message/SKB stream programs or `--kind reuseport-sockarray` on `sk_reuseport`, selects the appropriate helper from the current program type, and returns that helper result directly. On message/SKB stream programs, `--flags` is limited to `0` or `BPF_F_INGRESS`; reuseport selection leaves helper-specific flags to the kernel.

Read-only closure captures now lower as real constants for supported types (`int`, `bool`, `string`, `binary`, `nothing`, constant records, numeric constant lists, and homogeneous fixed arrays of scalar/binary/record constants`) instead of only working when inlined manually. That means existing Nushell structure can keep driving compile-time positions such as generic map names, for example `let map_name = "seen_paths"; $ctx.arg0.f_path | map-put $map_name $ctx.pid --kind hash`. Reassigned captured numeric scalars, strings, fixed binary values, numeric constant lists, homogeneous fixed arrays, and representable constant records now take the next step and lower as compiler-managed mutable globals backed by `.data` or `.bss`, so ordinary Nushell variable flow can express per-program state without dropping down to explicit maps for the smallest cases. Leading typed `mut` list initializers can also use homogeneous scalar/binary/record constants as fixed-array globals when the initializer provides the concrete length and layout, for example `mut entries: list<record<pid: int cpu: int>> = [{pid: 7, cpu: 2} {pid: 9, cpu: 3}]`; the same fixed-array layout is available for typed list fields nested inside typed record `mut` globals. That mutable path is still intentionally honest: it works for values with a real byte layout and tracked runtime metadata, and metadata-only record builders are accepted only when the compiler can derive a truthful fixed record layout, including nested record-builder fields, and materialize them on demand before the global store.

## Language Surface Policy

- Prefer ordinary Nushell syntax plus the small first-class eBPF command set (`emit`, `count`, `histogram`, `start-timer`, `stop-timer`, `read-str`, `read-kernel-str`, `adjust-packet`, `adjust-message`, `redirect`, `redirect-map`, and `redirect-socket`) whenever the operation has an honest language form. Ordinary Nushell primitives are preferred over helper wrappers too; `random int` lowers to `bpf_get_prandom_u32`.
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
| `random int` | Return a BPF pseudo-random integer using `bpf_get_prandom_u32`; eBPF supports the zero-argument form and compile-time bounded ranges covering at most `2^32` values |
| `start-timer` | Record start timestamp |
| `stop-timer` | Calculate elapsed time |
| `read-str` | Read string from user memory (`--max-len` to cap, default 128) |
| `read-kernel-str` | Read string from kernel memory (`--max-len` to cap, default 128) |
| `adjust-packet` | Packet relayout (`xdp`: `--head` / `--meta` / `--tail`; `tc_action` / `tc` / `tcx` / `netkit` / `sk_skb` / `sk_skb_parser`: `--head` / `--tail` / `--pull` / `--room`) |
| `adjust-message` | `sk_msg` byte-window and reshaping control (`--apply`, `--cork`, `--pull`, `--push`, or `--pop`) |
| `redirect` | XDP/tc_action/tc/tcx/netkit redirect by ifindex (`--peer` and `--neigh` select cls_act helper variants; optional `--flags`) |
| `redirect-map` | XDP redirect through a named devmap/devmap-hash/cpumap/xskmap (`--kind` required; optional `--flags`) |
| `redirect-socket` | `sk_msg`/`sk_skb`/`sk_skb_parser` redirect through a named sockmap/sockhash, or `sk_reuseport` selection through a reuseport-sockarray (`--kind` required; optional `--flags`) |
| `helper-call` | Escape hatch: call a modeled BPF helper by literal name, such as `bpf_get_current_pid_tgid` |
| `kfunc-call` | Escape hatch: call a typed kernel kfunc by literal name, resolved from kernel BTF when possible |
| `global-define` | Declare a named compiler-managed program global when a leading typed `mut` binding is not enough; `--zero` uses a runtime exemplar, and `--type` declares an explicit scalar/`bytes:N`/`string:N`/`list:int:N` (alias `list:i64:N`)/`array{type:N}`/nested `record{field:type,...}` layout either zero-initialized or from a compile-time constant initializer |
| `global-get` | Load a named compiler-managed program global declared with `global-define` or inferred from `global-set` |
| `global-set` | Store the pipeline input into a named compiler-managed program global |
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

Stack trace ID collection should normally use first-class context fields: `$ctx.kstack` for kernel stacks and `$ctx.ustack` for user stacks. The backing `bpf_get_stackid` helper is constrained to tracing/perf-style program families and stack-trace maps, with flags limited to the skip field plus `BPF_F_USER_STACK`, `BPF_F_FAST_STACK_CMP`, and `BPF_F_REUSE_STACKID`. `bpf_get_stack` remains available through `helper-call` for custom buffers, maps, and flags, and accepts a stack/map buffer with a nonnegative size, including `0`. `bpf_get_task_stack` is also modeled for task-pointer inputs such as `ctx.task`, with the same stack/map output-buffer and nonnegative-size checks. Stack-copy helper flags are limited to the skip field plus `BPF_F_USER_STACK` and `BPF_F_USER_BUILD_ID`.
Perf-event counter snapshots should normally use `ctx.perf_counter`, `ctx.perf_enabled`, and `ctx.perf_running`; the backing `bpf_perf_prog_read_value` helper is modeled and constrained to `perf_event` programs.
Perf-event-array counter reads are also modeled through `helper-call "bpf_perf_event_read" MAP FLAGS` and `helper-call "bpf_perf_event_read_value" MAP FLAGS BUF 24`; both require perf-event-array maps, require flags to fit `BPF_F_INDEX_MASK` / `BPF_F_CURRENT_CPU` (`0xffffffff`), and the value form requires a 24-byte `struct bpf_perf_event_value` buffer.
Branch-stack helpers are modeled for escape-hatch use through `helper-call`. The perf-event-only `bpf_read_branch_records` helper includes its context argument, stack/map output buffer, zero-size query behavior, and flags limited to `0` or `BPF_F_GET_BRANCH_RECORDS_SIZE`. The base `bpf_get_branch_snapshot` helper uses a stack/map `perf_branch_entry` buffer, accepts a null buffer only with size `0`, and requires reserved flags to be `0`.
Signal helpers are modeled as explicit escape hatches too: `helper-call "bpf_send_signal" SIG` targets the current process, and `helper-call "bpf_send_signal_thread" SIG` targets the current thread. They are intentionally not lifted into a first-class command because they have visible side effects.
Per-CPU kernel symbol helpers are modeled for explicit escape-hatch use: `helper-call "bpf_per_cpu_ptr" PERCPU_PTR CPU` returns a nullable kernel pointer for the requested CPU, while `helper-call "bpf_this_cpu_ptr" PERCPU_PTR` returns a non-null kernel pointer for the current CPU. `PERCPU_PTR` must already be a trusted kernel per-CPU pointer, such as a pointer derived from a kernel BTF symbol path; stack and map pointers are rejected.
Userspace memory copy helpers are modeled for explicit `helper-call` use: `bpf_copy_from_user` requires a stack/map destination buffer and a typed userspace source pointer, while `bpf_copy_from_user_task` also requires a `task_struct *` argument such as `ctx.task` and reserved flags `0`. Their destination size may be `0`, but nonzero sizes must fit the output buffer. `bpf_probe_write_user` is also modeled for tracing/LSM/perf escape-hatch use with a typed userspace destination pointer, stack/map source buffer, and positive size. It remains a hazardous debugging-only kernel helper; lockdown, capability, and user-context restrictions are still enforced by the kernel at load/attach/runtime.
Kprobe error injection is modeled through `helper-call "bpf_override_return" CTX RC` on entry kprobe-style surfaces (`kprobe`, `kprobe.multi`, and `ksyscall`). The compiler checks the raw context pointer shape, but the kernel still enforces `CONFIG_BPF_KPROBE_OVERRIDE`, GPL/license constraints, and the target function's `ALLOW_ERROR_INJECTION` eligibility.
TCP congestion-control struct_ops callbacks can use `helper-call "bpf_tcp_send_ack" TP RCV_NXT`, where `TP` must be a typed socket/TCP kernel pointer such as `struct tcp_sock *`. The generic program-type policy treats this as a `struct_ops` helper, and full `ProgramSpec` contexts further narrow it to `tcp_congestion_ops` callbacks; callback-specific availability remains kernel-enforced.
Syscall programs can use the modeled syscall helper escape hatches `helper-call "bpf_sys_bpf" CMD ATTR ATTR_SIZE`, `helper-call "bpf_btf_find_by_name_kind" NAME NAME_SIZE KIND 0`, `helper-call "bpf_sys_close" FD`, and `helper-call "bpf_kallsyms_lookup_name" NAME NAME_SIZE 0 RES`. `ATTR`, `NAME`, and `RES` must be stack/map-backed buffers with positive modeled sizes where applicable, and `RES` must cover an 8-byte `u64`. Live attach for `syscall:*` remains unsupported.
String formatting through `helper-call "bpf_snprintf" STR STR_SIZE FMT DATA DATA_LEN` is modeled as a raw escape hatch. `STR` and `DATA` must be stack/map-backed buffers, `FMT` must be a map/rodata-backed format string rather than a mutable stack string, `STR_SIZE` must be nonnegative, and `DATA_LEN` must be nonnegative and a multiple of 8. `helper-call "bpf_trace_vprintk" FMT FMT_SIZE DATA DATA_LEN` is also modeled for trace-debug formatting, with stack/map-backed format/data buffers, positive `FMT_SIZE`, and `DATA_LEN` as a nonnegative multiple of 8. BTF-backed formatting is modeled through `helper-call "bpf_snprintf_btf" STR STR_SIZE BTF_PTR 16 FLAGS`, where `BTF_PTR` is a stack/map-backed 16-byte `struct btf_ptr` record and `FLAGS` may only contain supported `BTF_F_*` bits (`0x0f`).
Iterator seq-file output is modeled through `helper-call "bpf_seq_write" SEQ DATA LEN`, `helper-call "bpf_seq_printf" SEQ FMT FMT_SIZE DATA DATA_LEN`, and `helper-call "bpf_seq_printf_btf" SEQ BTF_PTR 16 FLAGS` on `iter:*` programs. `SEQ` must be a kernel `seq_file *` value, `FMT`, `DATA`, and `BTF_PTR` must be stack/map-backed buffers, except `bpf_seq_printf` may use `0` for `DATA` when `DATA_LEN` is also `0`. `DATA_LEN` must be nonnegative and a multiple of 8 for `bpf_seq_printf`, and `FLAGS` may only contain modeled `BTF_F_*` bits (`0x0f`).
Path formatting through `helper-call "bpf_d_path" PATH BUF SIZE` is modeled for kernel `struct path *` inputs and stack/map output buffers. The compiler checks pointer spaces and nonnegative buffer sizes, including zero-size/null-buffer queries; the kernel still enforces the attach-target allowlist for this helper.
LSM binary-parameter options can be set through `helper-call "bpf_bprm_opts_set" BPRM FLAGS` on LSM programs. `BPRM` must be a kernel `linux_binprm *` such as the argument exposed by `lsm:bprm_check_security`; `FLAGS` may only contain modeled `BPF_F_BPRM_*` bits (`0x01`, currently `BPF_F_BPRM_SECUREEXEC`).
IMA hash helpers are modeled on the LSM helper surface: `helper-call "bpf_ima_inode_hash" INODE DST SIZE` accepts a kernel `inode *`, and `helper-call "bpf_ima_file_hash" FILE DST SIZE` accepts a kernel `file *`. `DST` must be a stack/map output buffer and `SIZE` must be positive; kernel sleepable-hook restrictions remain kernel-enforced.
Cgroup return-value helpers are modeled for explicit `helper-call` use on the kernel-supported cgroup hooks: `bpf_get_retval` takes no arguments and `bpf_set_retval` takes a scalar return value. The compiler rejects cgroup skb, sock_ops, and cgroup_sock_addr recvmsg/getpeername/getsockname surfaces to match the kernel helper allowlist.
TC-family programs can call `helper-call "bpf_skb_cgroup_classid" CTX` to retrieve the cgroup v1 net_cls classid from the packet's associated socket. This TC/TCX/Netkit skb helper is distinct from `ctx.cgroup_classid`, which lowers to `bpf_get_cgroup_classid`.
Socket lookup helpers `bpf_sk_lookup_tcp`, `bpf_sk_lookup_udp`, and `bpf_skc_lookup_tcp` are modeled for explicit `helper-call` use with stack/map tuple buffers, positive tuple sizes, and reserved flags `0`; ordinary `ctx.sk.*` projections avoid spelling these helpers directly. Socket-cast helpers such as `bpf_skc_to_tcp_sock`, `bpf_skc_to_tcp6_sock`, `bpf_skc_to_mptcp_sock`, and `bpf_skc_to_unix_sock` are also modeled as escape hatches for typed kernel socket pointers, with nullable typed returns and socket-ref provenance checks.
Raw map-value spin locks are modeled through `helper-call "bpf_spin_lock" LOCK_PTR` and `helper-call "bpf_spin_unlock" LOCK_PTR` on non-tracing, non-socket-filter helper-capable program families. `LOCK_PTR` must be a non-null map-value pointer with at least four accessible bytes. The compiler models the verifier lifetime rules: only one `bpf_spin_lock` may be held, unlock requires a matching lock on all paths, helper/kfunc/subfunction calls are rejected while the lock is held, and every return path must release it. Kernel BTF requirements for a top-level `struct bpf_spin_lock` field in hash/array map values are not fully validated yet.
Raw syncookie helpers `bpf_tcp_raw_gen_syncookie_ipv4`, `bpf_tcp_raw_gen_syncookie_ipv6`, `bpf_tcp_raw_check_syncookie_ipv4`, and `bpf_tcp_raw_check_syncookie_ipv6` are modeled on XDP/TC-style programs for packet-header pointers. IPv4 helpers require a 20-byte IP header, IPv6 helpers require a 40-byte IP header, check helpers require a 20-byte TCP header, and raw generation sizes the TCP header from `TH_LEN`.
Namespace-aware PID/TGID reads are available through `helper-call "bpf_get_ns_current_pid_tgid" DEV INO NSDATA 8`, where `NSDATA` is an 8-byte stack/map buffer containing `pid` and `tgid` as two `u32` values.
String-to-integer parsing helpers `bpf_strtol` and `bpf_strtoul` are modeled for escape-hatch use with stack/map input buffers, 8-byte stack/map result slots, and base-selector flags restricted to `0`, `8`, `10`, or `16`. `bpf_strncmp` is also modeled as an escape hatch: `S1` must be a stack/map buffer with positive `S1_SIZE`, while `S2` must be a read-only map/rodata string.
Legacy `bpf_probe_read_str` is modeled for escape-hatch compatibility on the same tracing/LSM/perf surfaces as legacy `bpf_probe_read`, but normal string reads should use `read-str` or `read-kernel-str` so the compiler can choose the explicit user/kernel helper.
BPF packet-output helpers `bpf_skb_output` and `bpf_xdp_output` are modeled for tracing/perf-style programs that receive typed `sk_buff` / `xdp_buff` context pointers; they use perf-event-array maps and stack/map data buffers sized by the helper `size` argument, and are not treated as ordinary XDP/TC packet-program helpers.
BTF-backed tracing argument count is available as `ctx.arg_count`; the lower-level `bpf_get_func_arg`, `bpf_get_func_ret`, and `bpf_get_func_arg_cnt` helpers are modeled for explicit `helper-call` use when fixed `ctx.argN` / `ctx.retval` projections are not the right fit.

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
