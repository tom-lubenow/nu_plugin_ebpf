use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn raw_tracepoint_arg_offset(index: usize) -> Result<i16, CompileError> {
        let byte_offset = index.checked_mul(8).ok_or_else(|| {
            CompileError::UnsupportedInstruction("raw tracepoint arg offset overflow".into())
        })?;
        i16::try_from(byte_offset).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "raw tracepoint arg index {} is too large",
                index
            ))
        })
    }

    pub(super) fn perf_event_data_offsets() -> Result<(i16, i16), CompileError> {
        #[cfg(target_arch = "x86_64")]
        {
            Ok((168, 176))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(CompileError::UnsupportedInstruction(
                "perf_event ctx.sample_period/ctx.addr are not yet modeled on this architecture"
                    .to_string(),
            ))
        }
    }

    pub(super) fn xdp_md_offsets() -> (i16, i16, i16, i16, i16, i16) {
        // struct xdp_md {
        //     __u32 data;
        //     __u32 data_end;
        //     __u32 data_meta;
        //     __u32 ingress_ifindex;
        //     __u32 rx_queue_index;
        //     __u32 egress_ifindex;
        // };
        (0, 4, 8, 12, 16, 20)
    }

    pub(crate) fn sk_buff_offsets() -> (i16, i16, i16, i16, i16, i16, i16) {
        // struct __sk_buff {
        //     __u32 len;
        //     ...
        //     __u32 ingress_ifindex;
        //     __u32 ifindex;
        //     __u32 tc_index;
        //     ...
        //     __u32 hash;
        //     ...
        //     __u32 data;
        //     __u32 data_end;
        // };
        (0, 76, 80, 36, 40, 44, 68)
    }

    pub(super) fn sk_buff_data_meta_offset() -> i16 {
        // struct __sk_buff {
        //     ...
        //     __u32 remote_port;
        //     __u32 local_port;
        //     __u32 data_meta;
        // };
        140
    }

    pub(crate) fn sk_buff_tstamp_offset() -> i16 {
        // struct __sk_buff {
        //     ...
        //     __u32 data_meta;
        //     struct bpf_flow_keys *flow_keys;
        //     __u64 tstamp;
        // };
        152
    }

    pub(super) fn sk_buff_tstamp_type_offset() -> i16 {
        // struct __sk_buff {
        //     ...
        //     __u64 tstamp;
        //     __u32 wire_len;
        //     __u32 gso_segs;
        //     struct bpf_sock *sk;
        //     __u32 gso_size;
        //     __u8  tstamp_type;
        // };
        180
    }

    pub(super) fn sk_buff_packet_meta_offsets() -> (i16, i16) {
        // struct __sk_buff {
        //     __u32 len;
        //     __u32 pkt_type;
        //     __u32 mark;
        //     __u32 queue_mapping;
        // };
        (4, 12)
    }

    pub(super) fn sk_buff_vlan_offsets() -> (i16, i16, i16, i16) {
        // struct __sk_buff {
        //     ...
        //     __u32 protocol;      // stored in network byte order
        //     __u32 vlan_present;
        //     __u32 vlan_tci;
        //     __u32 vlan_proto;    // stored in network byte order
        // };
        (16, 20, 24, 28)
    }

    pub(crate) fn sk_buff_cb_offset() -> i16 {
        // struct __sk_buff {
        //     ...
        //     __u32 cb[5];
        // };
        48
    }

    pub(crate) fn sk_buff_extended_meta_offsets() -> (i16, i16, i16, i16, i16, i16) {
        // struct __sk_buff {
        //     ...
        //     __u32 tc_classid;
        //     ...
        //     __u32 napi_id;
        //     ...
        //     __u32 wire_len;
        //     __u32 gso_segs;
        //     ...
        //     __u32 gso_size;
        //     ...
        //     __u64 hwtstamp;
        // };
        (72, 84, 160, 164, 176, 184)
    }

    pub(crate) fn sk_buff_mark_priority_offsets() -> (i16, i16) {
        // struct __sk_buff {
        //     __u32 len;
        //     __u32 pkt_type;
        //     __u32 mark;
        //     ...
        //     __u32 priority;
        // };
        (8, 32)
    }

    pub(super) fn sk_buff_socket_offsets() -> (i16, i16, i16, i16, i16, i16, i16, i16) {
        // struct __sk_buff {
        //     ...
        //     __u32 data;
        //     __u32 data_end;
        //     __u32 napi_id;
        //     __u32 family;
        //     __u32 remote_ip4;     // network byte order
        //     __u32 local_ip4;      // network byte order
        //     __u32 remote_ip6[4];  // network byte order
        //     __u32 local_ip6[4];   // network byte order
        //     __u32 remote_port;    // network byte order (u32)
        //     __u32 local_port;     // host byte order
        //     ...
        //     struct bpf_sock *sk;
        // };
        (88, 92, 96, 100, 116, 132, 136, 168)
    }

    pub(super) fn sk_msg_md_offsets() -> (i16, i16, i16, i16, i16, i16, i16, i16, i16, i16) {
        // struct sk_msg_md {
        //     __bpf_md_ptr(void *, data);
        //     __bpf_md_ptr(void *, data_end);
        //     __u32 family;
        //     __u32 remote_ip4;     // network byte order
        //     __u32 local_ip4;      // network byte order
        //     __u32 remote_ip6[4];  // network byte order
        //     __u32 local_ip6[4];   // network byte order
        //     __u32 remote_port;    // network byte order (u32)
        //     __u32 local_port;     // host byte order
        //     __u32 size;
        // };
        (0, 8, 16, 20, 24, 28, 44, 60, 64, 68)
    }

    pub(super) fn sk_msg_md_sock_offset() -> i16 {
        72
    }

    pub(in crate::compiler::mir_to_ebpf) fn bpf_sock_addr_offsets()
    -> (i16, i16, i16, i16, i16, i16, i16, i16, i16, i16) {
        // struct bpf_sock_addr {
        //     __u32 user_family;
        //     __u32 user_ip4;
        //     __u32 user_ip6[4];
        //     __u32 user_port;
        //     __u32 family;
        //     __u32 type;
        //     __u32 protocol;
        //     __u32 msg_src_ip4;
        //     __u32 msg_src_ip6[4];
        //     struct bpf_sock *sk;
        // };
        (0, 4, 8, 24, 28, 32, 36, 40, 44, 64)
    }

    pub(in crate::compiler::mir_to_ebpf) fn bpf_sysctl_offsets() -> (i16, i16) {
        // struct bpf_sysctl {
        //     __u32 write;
        //     __u32 file_pos;
        // };
        (0, 4)
    }

    pub(super) fn bpf_cgroup_dev_ctx_offsets() -> (i16, i16, i16) {
        // struct bpf_cgroup_dev_ctx {
        //     __u32 access_type;
        //     __u32 major;
        //     __u32 minor;
        // };
        (0, 4, 8)
    }

    pub(in crate::compiler::mir_to_ebpf) fn bpf_sockopt_offsets()
    -> (i16, i16, i16, i16, i16, i16, i16) {
        // struct bpf_sockopt {
        //     __u64 sk;
        //     __u64 optval;
        //     __u64 optval_end;
        //     __s32 level;
        //     __s32 optname;
        //     __s32 optlen;
        //     __s32 retval;
        // };
        (0, 8, 16, 24, 28, 32, 36)
    }

    pub(in crate::compiler::mir_to_ebpf) fn bpf_sock_offsets() -> (
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
        i16,
    ) {
        // struct bpf_sock {
        //     __u32 bound_dev_if;
        //     __u32 family;
        //     __u32 type;
        //     __u32 protocol;
        //     __u32 mark;
        //     __u32 priority;
        //     __u32 src_ip4;
        //     __u32 src_ip6[4];
        //     __u32 src_port;
        //     __be16 dst_port;
        //     __u32 dst_ip4;
        //     __u32 dst_ip6[4];
        //     ...
        //     __u32 state;
        //     __s32 rx_queue_mapping;
        // };
        (0, 4, 8, 12, 16, 20, 24, 28, 44, 48, 52, 56, 72, 76)
    }

    pub(super) fn bpf_sk_lookup_offsets() -> (i16, i16, i16, i16, i16, i16, i16, i16, i16, i16) {
        // struct bpf_sk_lookup {
        //     union { struct bpf_sock *sk; __u64 cookie; };
        //     __u32 family;
        //     __u32 protocol;
        //     __u32 remote_ip4;     // network byte order
        //     __u32 remote_ip6[4];  // network byte order
        //     __be16 remote_port;   // network byte order
        //     ...
        //     __u32 local_ip4;      // network byte order
        //     __u32 local_ip6[4];   // network byte order
        //     __u32 local_port;     // host byte order
        //     __u32 ingress_ifindex;
        // };
        (0, 8, 12, 16, 20, 36, 40, 44, 60, 64)
    }

    pub(super) fn bpf_sock_ops_offsets()
    -> (i16, i16, i16, i16, i16, i16, i16, i16, i16, i16, i16, i16) {
        // struct bpf_sock_ops {
        //     __u32 op;
        //     union { __u32 args[4]; __u32 reply; __u32 replylong[4]; };
        //     __u32 family;
        //     __u32 remote_ip4;     // network byte order
        //     __u32 local_ip4;      // network byte order
        //     __u32 remote_ip6[4];  // network byte order
        //     __u32 local_ip6[4];   // network byte order
        //     __u32 remote_port;    // network byte order
        //     __u32 local_port;     // host byte order
        //     __u32 is_fullsock;
        //     ...
        //     __u32 bpf_sock_ops_cb_flags;
        //     __u32 state;
        //     ...
        //     struct bpf_sock *sk;
        // };
        (0, 20, 24, 28, 32, 48, 64, 68, 72, 84, 88, 184)
    }

    pub(in crate::compiler::mir_to_ebpf) fn bpf_sock_ops_args_offset() -> i16 {
        4
    }

    pub(super) fn bpf_sock_ops_tcp_field_offsets() -> (i16, i16, i16, i16) {
        // struct bpf_sock_ops {
        //     ...
        //     __u32 snd_cwnd;
        //     __u32 srtt_us;
        //     ...
        //     __u32 rtt_min;
        //     __u32 snd_ssthresh;
        // };
        (76, 80, 92, 96)
    }

    pub(super) fn bpf_sock_ops_progress_offsets() -> (i16, i16, i16, i16, i16, i16, i16, i16) {
        // struct bpf_sock_ops {
        //     ...
        //     __u32 rcv_nxt;
        //     __u32 snd_nxt;
        //     __u32 snd_una;
        //     ...
        //     __u32 packets_out;
        //     __u32 retrans_out;
        //     __u32 total_retrans;
        //     ...
        //     __u64 bytes_received;
        //     __u64 bytes_acked;
        // };
        (100, 104, 108, 128, 132, 136, 168, 176)
    }

    pub(in crate::compiler::mir_to_ebpf) fn bpf_sock_ops_extra_metric_offsets()
    -> (i16, i16, i16, i16, i16, i16, i16, i16, i16, i16, i16) {
        // struct bpf_sock_ops {
        //     ...
        //     __u32 mss_cache;
        //     __u32 ecn_flags;
        //     __u32 rate_delivered;
        //     __u32 rate_interval_us;
        //     ...
        //     __u32 segs_in;
        //     __u32 data_segs_in;
        //     __u32 segs_out;
        //     __u32 data_segs_out;
        //     __u32 lost_out;
        //     __u32 sacked_out;
        //     __u32 sk_txhash;
        // };
        (112, 116, 120, 124, 140, 144, 148, 152, 156, 160, 164)
    }

    pub(super) fn bpf_sock_ops_skb_field_offsets() -> (i16, i16, i16) {
        // struct bpf_sock_ops {
        //     ...
        //     __u32 skb_len;
        //     __u32 skb_tcp_flags;
        //     __u64 skb_hwtstamp;
        // };
        (208, 212, 216)
    }

    pub(super) fn bpf_sock_ops_packet_data_offsets() -> (i16, i16) {
        // struct bpf_sock_ops {
        //     ...
        //     void *skb_data;
        //     void *skb_data_end;
        // };
        (192, 200)
    }

    pub(super) fn compile_ctx_u32_array_to_stack(
        &mut self,
        dst: EbpfReg,
        slot: Option<StackSlotId>,
        base_offset: i16,
        count: usize,
        field_name: &str,
        normalize_big_endian: bool,
    ) -> Result<(), CompileError> {
        let slot = slot.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{field_name} requires a stack backing slot"
            ))
        })?;
        let slot_offset = *self.slot_offsets.get(&slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!("{field_name} stack slot not found"))
        })?;

        for index in 0..count {
            let word_offset = base_offset + (index as i16 * 4);
            let dst_offset = slot_offset + (index as i16 * 4);
            self.instructions
                .push(EbpfInsn::ldxw(EbpfReg::R0, EbpfReg::R9, word_offset));
            if normalize_big_endian {
                self.instructions.push(EbpfInsn::end32_to_be(EbpfReg::R0));
            }
            self.instructions
                .push(EbpfInsn::stxw(EbpfReg::R10, dst_offset, EbpfReg::R0));
        }

        self.instructions
            .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(dst, slot_offset as i32));
        Ok(())
    }

    pub(super) fn packet_context_kind(&self) -> Result<PacketContextKind, CompileError> {
        self.probe_ctx
            .and_then(|ctx| ctx.packet_context_kind())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "packet context fields require a packet-context program type".to_string(),
                )
            })
    }

    pub(super) fn data_meta_context_kind(&self) -> Result<PacketContextKind, CompileError> {
        self.probe_ctx
            .and_then(|ctx| ctx.data_meta_context_kind())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "ctx.data_meta is only available on xdp and tc programs".to_string(),
                )
            })
    }
}
