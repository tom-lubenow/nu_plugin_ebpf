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

    pub(super) fn compile_perf_event_value_field(
        &mut self,
        dst: EbpfReg,
        member_offset: i16,
    ) -> Result<(), CompileError> {
        const PERF_EVENT_VALUE_SIZE: i16 = 24;

        self.check_stack_space(PERF_EVENT_VALUE_SIZE)?;
        self.stack_offset -= PERF_EVENT_VALUE_SIZE;
        let value_offset = self.stack_offset;

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, value_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(
            EbpfReg::R3,
            PERF_EVENT_VALUE_SIZE as i32,
        ));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::PerfProgReadValue));
        self.instructions.push(EbpfInsn::ldxdw(
            dst,
            EbpfReg::R10,
            value_offset + member_offset,
        ));

        self.stack_offset += PERF_EVENT_VALUE_SIZE;
        Ok(())
    }

    pub(crate) fn sk_buff_cb_offset() -> i16 {
        // struct __sk_buff {
        //     ...
        //     __u32 cb[5];
        // };
        48
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

    pub(in crate::compiler::mir_to_ebpf) fn bpf_sock_ops_args_offset() -> i16 {
        4
    }

    pub(super) fn bpf_nf_ctx_offsets() -> (i16, i16) {
        // struct bpf_nf_ctx {
        //     const struct nf_hook_state *state;
        //     struct sk_buff *skb;
        // };
        (0, 8)
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
                    "ctx.data_meta is only available on xdp, tc_action, tc, tcx, and netkit programs"
                        .to_string(),
                )
            })
    }
}
