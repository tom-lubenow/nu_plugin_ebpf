use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn compile_histogram(&mut self, value_reg: EbpfReg) -> Result<(), CompileError> {
        // Allocate stack for key (bucket) and value (count)
        self.check_stack_space(16)?;
        let key_offset = self.stack_offset - 8;
        let value_offset = self.stack_offset - 16;
        self.stack_offset -= 16;

        // Compute log2 bucket using binary search
        // Save value to R0 for manipulation, bucket accumulator in R1
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R0, value_reg));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R1, 0));

        // If value <= 0, bucket = 0
        // JLE R0, 0, skip_log2 (offset will be filled in later)
        let skip_log2_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            0,
            0, // offset placeholder
        ));

        // Binary search for highest bit
        // Check >= 2^32
        self.emit_log2_check(32)?;
        self.emit_log2_check(16)?;
        self.emit_log2_check(8)?;
        self.emit_log2_check(4)?;
        self.emit_log2_check(2)?;
        self.emit_log2_check(1)?;

        // Fix up skip_log2 jump to skip past log2 computation
        let skip_log2_offset = (self.instructions.len() - skip_log2_idx - 1) as i16;
        self.instructions[skip_log2_idx].offset = skip_log2_offset;

        // Store bucket (R1) to stack
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R1));

        // Map lookup
        let lookup_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: lookup_reloc,
            map_name: HISTOGRAM_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If NULL, jump to init
        let init_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            0,
            0,
        ));

        // Exists - increment in place
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R0, 0));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R1, 1));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R0, 0, EbpfReg::R1));

        // Jump to done
        let done_jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));

        // Init path
        let init_offset = (self.instructions.len() - init_idx - 1) as i16;
        self.instructions[init_idx].offset = init_offset;

        // Store 1 to value
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R1, 1));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, value_offset, EbpfReg::R1));

        // Map update
        let update_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: update_reloc,
            map_name: HISTOGRAM_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R3, value_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        // Done
        let done_offset = (self.instructions.len() - done_jmp_idx - 1) as i16;
        self.instructions[done_jmp_idx].offset = done_offset;

        Ok(())
    }
    /// Helper for log2 computation - check if value >= 2^bits
    fn emit_log2_check(&mut self, bits: i32) -> Result<(), CompileError> {
        if bits >= 32 {
            // Need 64-bit compare against a register
            self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R2, 1));
            self.instructions
                .push(EbpfInsn::lsh64_imm(EbpfReg::R2, bits));
            self.instructions.push(EbpfInsn::new(
                opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_X,
                EbpfReg::R0.as_u8(),
                EbpfReg::R2.as_u8(),
                2,
                0,
            ));
        } else {
            // JLT R0, 2^bits, skip (2 instructions)
            self.instructions.push(EbpfInsn::new(
                opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
                EbpfReg::R0.as_u8(),
                0,
                2,
                1 << bits,
            ));
        }
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R1, bits));
        self.instructions
            .push(EbpfInsn::rsh64_imm(EbpfReg::R0, bits));
        Ok(())
    }

    /// Compile start-timer: store current ktime keyed by TID
    pub(super) fn compile_start_timer(&mut self) -> Result<(), CompileError> {
        // Allocate stack for key (pid_tgid) and value (timestamp)
        self.check_stack_space(16)?;
        let key_offset = self.stack_offset - 8;
        let value_offset = self.stack_offset - 16;
        self.stack_offset -= 16;

        // Get current pid_tgid as key
        self.instructions
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R0));

        // Get current time
        self.instructions
            .push(EbpfInsn::call(BpfHelper::KtimeGetNs));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, value_offset, EbpfReg::R0));

        // Map update
        let update_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: update_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R3, value_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        Ok(())
    }

    /// Compile stop-timer: lookup start time, compute delta, delete entry
    pub(super) fn compile_stop_timer(&mut self, dst_reg: EbpfReg) -> Result<(), CompileError> {
        // Allocate stack for key (pid_tgid) and start timestamp
        self.check_stack_space(16)?;
        let key_offset = self.stack_offset - 8;
        let start_offset = self.stack_offset - 16;
        self.stack_offset -= 16;

        // Get current pid_tgid as key
        self.instructions
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R0));

        // Map lookup
        let lookup_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: lookup_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If NULL, return 0
        let no_timer_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            0,
            0,
        ));

        // Load start timestamp and store it on stack
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R0, 0));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, start_offset, EbpfReg::R1));

        // Get current time
        self.instructions
            .push(EbpfInsn::call(BpfHelper::KtimeGetNs));

        // Reload start timestamp and compute delta = current - start
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R10, start_offset));
        self.instructions
            .push(EbpfInsn::sub64_reg(EbpfReg::R0, EbpfReg::R1));

        // Preserve delta across map_delete helper call (R1-R5 are caller-clobbered).
        // Reuse the temporary stack slot that previously held the start timestamp.
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, start_offset, EbpfReg::R0));

        // Delete map entry
        let delete_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: delete_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapDeleteElem));

        // Restore saved delta after helper clobbers caller-saved registers.
        self.instructions
            .push(EbpfInsn::ldxdw(dst_reg, EbpfReg::R10, start_offset));

        // Jump to done
        let done_jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));

        // No timer path - set dst to 0
        let no_timer_offset = (self.instructions.len() - no_timer_idx - 1) as i16;
        self.instructions[no_timer_idx].offset = no_timer_offset;
        self.instructions.push(EbpfInsn::mov64_imm(dst_reg, 0));

        // Done
        let done_offset = (self.instructions.len() - done_jmp_idx - 1) as i16;
        self.instructions[done_jmp_idx].offset = done_offset;

        Ok(())
    }
}
