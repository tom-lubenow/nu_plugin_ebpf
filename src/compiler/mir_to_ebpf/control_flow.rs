use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn compile_jump(&mut self, target: BlockId) {
        let jump_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0)); // Placeholder
        self.pending_jumps.push((jump_idx, target));
    }

    pub(super) fn compile_branch(
        &mut self,
        cond: VReg,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        let cond_reg = self.ensure_reg(cond)?;

        // JNE (jump if not equal to 0) to if_true
        let jne_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
            cond_reg.as_u8(),
            0,
            0, // Placeholder
            0, // Compare against 0
        ));
        self.pending_jumps.push((jne_idx, if_true));

        // Fall through or jump to if_false
        let jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));
        self.pending_jumps.push((jmp_idx, if_false));

        Ok(())
    }

    pub(super) fn compile_return(&mut self, val: &Option<MirValue>) -> Result<(), CompileError> {
        match val {
            Some(MirValue::VReg(v)) => {
                let src = self.ensure_reg(*v)?;
                if src != EbpfReg::R0 {
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R0, src));
                }
            }
            Some(MirValue::Const(c)) => {
                self.instructions
                    .push(EbpfInsn::mov64_imm(EbpfReg::R0, *c as i32));
            }
            Some(MirValue::StackSlot(_)) => {
                return Err(CompileError::UnsupportedInstruction(
                    "Stack slot in return".into(),
                ));
            }
            None => {
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
            }
        }
        self.restore_callee_saved();
        self.instructions.push(EbpfInsn::exit());
        Ok(())
    }

    pub(super) fn compile_loop_header(
        &mut self,
        counter: VReg,
        limit: i64,
        body: BlockId,
        exit: BlockId,
    ) -> Result<(), CompileError> {
        // Bounded loop header for eBPF verifier compliance
        // counter < limit ? jump to body : jump to exit
        let counter_reg = self.ensure_reg(counter)?;

        // Compare counter against limit
        // JSLT: jump if counter < limit (signed)
        let jlt_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_K,
            counter_reg.as_u8(),
            0,
            0, // Placeholder - will be fixed up
            limit as i32,
        ));
        self.pending_jumps.push((jlt_idx, body));

        // Fall through to exit
        let jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));
        self.pending_jumps.push((jmp_idx, exit));

        Ok(())
    }

    pub(super) fn compile_loop_back(
        &mut self,
        counter: VReg,
        step: i64,
        header: BlockId,
    ) -> Result<(), CompileError> {
        // Increment counter and jump back to header
        let counter_reg = self.ensure_reg(counter)?;

        // Add step to counter
        self.instructions
            .push(EbpfInsn::add64_imm(counter_reg, step as i32));

        // Jump back to loop header
        let jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));
        self.pending_jumps.push((jmp_idx, header));

        Ok(())
    }

    pub(super) fn compile_tail_call_inst(
        &mut self,
        prog_map: &crate::compiler::mir::MapRef,
        index: &MirValue,
    ) -> Result<(), CompileError> {
        if prog_map.kind != MapKind::ProgArray {
            return Err(CompileError::UnsupportedInstruction(format!(
                "Tail call requires prog array map, got {:?} for '{}'",
                prog_map.kind, prog_map.name
            )));
        }
        self.tail_call_maps.insert(prog_map.name.clone());
        self.compile_tail_call(&prog_map.name, index)?;
        // Tail call helper does not return on success. If it does return, tail call failed;
        // terminate the current function with a default 0.
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
        self.restore_callee_saved();
        self.instructions.push(EbpfInsn::exit());
        Ok(())
    }
}
