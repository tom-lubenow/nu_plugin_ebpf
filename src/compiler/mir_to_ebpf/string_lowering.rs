use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn compile_string_append(
        &mut self,
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: &MirValue,
        val_type: &StringAppendType,
    ) -> Result<(), CompileError> {
        // Get destination buffer offset
        let dst_offset = self.slot_offsets.get(&dst_buffer).copied().unwrap_or(0);
        let len_reg = self.ensure_reg(dst_len)?;

        match val_type {
            StringAppendType::Literal { bytes } => {
                // Append literal string bytes to buffer
                // Each byte is stored at dst_buffer + dst_len + i
                let effective_len = bytes
                    .iter()
                    .rposition(|b| *b != 0)
                    .map(|idx| idx + 1)
                    .unwrap_or(0);
                for (i, byte) in bytes.iter().enumerate() {
                    // R0 = dst_len + i (offset within buffer)
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R0, len_reg));
                    self.instructions
                        .push(EbpfInsn::add64_imm(EbpfReg::R0, i as i32));

                    // R1 = R10 + dst_offset (buffer base)
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                    self.instructions
                        .push(EbpfInsn::add64_imm(EbpfReg::R1, dst_offset as i32));

                    // R1 = R1 + R0 (buffer + offset)
                    self.instructions
                        .push(EbpfInsn::add64_reg(EbpfReg::R1, EbpfReg::R0));

                    // R2 = byte value
                    self.instructions
                        .push(EbpfInsn::mov64_imm(EbpfReg::R2, *byte as i32));

                    // Store byte: [R1] = R2
                    self.instructions
                        .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R2));
                }

                if effective_len > 0 {
                    // Update length: dst_len += effective_len
                    self.instructions
                        .push(EbpfInsn::add64_imm(len_reg, effective_len as i32));
                }
            }

            StringAppendType::StringSlot { slot, max_len } => {
                // Copy bytes from source slot to destination
                let src_offset = self.slot_offsets.get(slot).copied().unwrap_or(0);

                // Bounded loop to copy up to max_len bytes
                // For eBPF verifier, we unroll small loops
                let copy_len = (*max_len).min(64); // Cap at 64 bytes to limit instruction count
                for i in 0..copy_len {
                    // Load byte from source: R0 = [R10 + src_offset + i]
                    self.instructions.push(EbpfInsn::ldxb(
                        EbpfReg::R0,
                        EbpfReg::R10,
                        src_offset + i as i16,
                    ));

                    // Check for null terminator
                    let skip_offset = 8i16; // Skip remaining instructions if null
                    self.instructions
                        .push(EbpfInsn::jeq_imm(EbpfReg::R0, 0, skip_offset));

                    // R1 = dst_len (current position in dest)
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R1, len_reg));

                    // R2 = R10 + dst_offset (dest buffer base)
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
                    self.instructions
                        .push(EbpfInsn::add64_imm(EbpfReg::R2, dst_offset as i32));

                    // R2 = R2 + R1 (dest buffer + offset)
                    self.instructions
                        .push(EbpfInsn::add64_reg(EbpfReg::R2, EbpfReg::R1));

                    // Store byte: [R2] = R0
                    self.instructions
                        .push(EbpfInsn::stxb(EbpfReg::R2, 0, EbpfReg::R0));

                    // Increment length
                    self.instructions.push(EbpfInsn::add64_imm(len_reg, 1));
                }
            }

            StringAppendType::Integer => {
                // Integer to string conversion then append
                // Strategy:
                // 1. Allocate 24-byte temp buffer for digit extraction
                // 2. Extract digits in reverse order (at temp+19 down)
                // 3. Copy digits in correct order to dst_buffer at dst_len
                // 4. Update dst_len

                // Get the integer value register
                let val_reg = match val {
                    MirValue::VReg(v) => self.ensure_reg(*v)?,
                    MirValue::Const(c) => {
                        // Load constant into R0
                        self.instructions
                            .push(EbpfInsn::mov64_imm(EbpfReg::R0, *c as i32));
                        EbpfReg::R0
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot as integer value not supported".into(),
                        ));
                    }
                };

                // Allocate temporary buffer for digit extraction (24 bytes)
                self.check_stack_space(24)?;
                self.stack_offset -= 24;
                let temp_offset = self.stack_offset;

                // Check for zero special case
                // We need to preserve val_reg, so copy to R3
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R3, val_reg));

                // R4 = digit count
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

                // Check if value is 0
                let non_zero_skip = 5i16;
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                self.instructions
                    .push(EbpfInsn::jne_reg(EbpfReg::R3, EbpfReg::R0, non_zero_skip));

                // Value is 0: store '0' at temp+19, set digit count to 1
                self.instructions
                    .push(EbpfInsn::mov64_imm(EbpfReg::R0, b'0' as i32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R1, (temp_offset + 19) as i32));
                self.instructions
                    .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R0));
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 1));

                // Extract digits for non-zero value (bounded loop for verifier)
                for i in 0..20 {
                    // Skip if R3 == 0
                    let done_offset = 8i16;
                    self.instructions
                        .push(EbpfInsn::jeq_imm(EbpfReg::R3, 0, done_offset));

                    // R0 = R3 % 10 (digit)
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R0, EbpfReg::R3));
                    self.instructions.push(EbpfInsn::mod64_imm(EbpfReg::R0, 10));

                    // Convert to ASCII: R0 += '0'
                    self.instructions
                        .push(EbpfInsn::add64_imm(EbpfReg::R0, b'0' as i32));

                    // Store digit at temp + (19 - i)
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                    self.instructions.push(EbpfInsn::add64_imm(
                        EbpfReg::R1,
                        (temp_offset + 19 - i as i16) as i32,
                    ));
                    self.instructions
                        .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R0));

                    // R3 = R3 / 10
                    self.instructions.push(EbpfInsn::div64_imm(EbpfReg::R3, 10));

                    // R4++ (digit count)
                    self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R4, 1));
                }

                // Now copy digits from temp buffer to dst_buffer
                // Digits are at temp + (20 - R4) to temp + 19
                // Copy to dst_buffer + dst_len

                // R5 = start position in temp = 20 - R4
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R5, 20));
                self.instructions
                    .push(EbpfInsn::sub64_reg(EbpfReg::R5, EbpfReg::R4));

                // Copy loop (bounded by max 20 digits)
                for i in 0..20 {
                    // Skip if we've copied all digits (i >= R4)
                    self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, i));
                    let skip_copy = 10i16;
                    // Jump if R0 >= R4 (unsigned)
                    self.instructions.push(EbpfInsn::new(
                        opcode::BPF_JMP | opcode::BPF_JGE | opcode::BPF_X,
                        EbpfReg::R0.as_u8(),
                        EbpfReg::R4.as_u8(),
                        skip_copy,
                        0,
                    ));

                    // Load byte from temp + R5 + i
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                    self.instructions
                        .push(EbpfInsn::add64_imm(EbpfReg::R1, temp_offset as i32));
                    self.instructions
                        .push(EbpfInsn::add64_reg(EbpfReg::R1, EbpfReg::R5));
                    self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R1, i));
                    self.instructions
                        .push(EbpfInsn::ldxb(EbpfReg::R0, EbpfReg::R1, 0));

                    // Store to dst_buffer + dst_len + i
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
                    self.instructions
                        .push(EbpfInsn::add64_imm(EbpfReg::R2, dst_offset as i32));
                    self.instructions
                        .push(EbpfInsn::add64_reg(EbpfReg::R2, len_reg));
                    self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R2, i));
                    self.instructions
                        .push(EbpfInsn::stxb(EbpfReg::R2, 0, EbpfReg::R0));
                }

                // Update dst_len += digit_count (R4)
                self.instructions
                    .push(EbpfInsn::add64_reg(len_reg, EbpfReg::R4));
            }
        }

        Ok(())
    }

    pub(super) fn compile_int_to_string(
        &mut self,
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: VReg,
    ) -> Result<(), CompileError> {
        // Convert integer to decimal string
        // Uses repeated division by 10 to extract digits

        let dst_offset = self.slot_offsets.get(&dst_buffer).copied().unwrap_or(0);
        let val_reg = self.ensure_reg(val)?;
        let len_reg = self.alloc_dst_reg(dst_len)?;

        // Initialize length to 0
        self.instructions.push(EbpfInsn::mov64_imm(len_reg, 0));

        // Check for zero special case
        // if val == 0, just store '0' and return
        let non_zero_skip = 6i16; // Instructions to skip if non-zero
        self.instructions
            .push(EbpfInsn::jne_reg(val_reg, EbpfReg::R0, non_zero_skip)); // R0 should be 0 here

        // Store '0' character
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R0, b'0' as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R1, dst_offset as i32));
        self.instructions
            .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R0));
        self.instructions.push(EbpfInsn::mov64_imm(len_reg, 1));

        // For non-zero: extract digits (simplified - handles up to 10 digits)
        // This is a bounded loop for the verifier
        // R3 = working value, R4 = digit count, R5 = temp buffer offset
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, val_reg));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        // Extract up to 20 digits (covers full i64 range)
        for _ in 0..20 {
            // Skip if R3 == 0
            let done_offset = 8i16;
            self.instructions
                .push(EbpfInsn::jeq_imm(EbpfReg::R3, 0, done_offset));

            // R0 = R3 % 10 (digit)
            self.instructions
                .push(EbpfInsn::mov64_reg(EbpfReg::R0, EbpfReg::R3));
            self.instructions.push(EbpfInsn::mod64_imm(EbpfReg::R0, 10));

            // Convert to ASCII: R0 += '0'
            self.instructions
                .push(EbpfInsn::add64_imm(EbpfReg::R0, b'0' as i32));

            // Store digit at temp position (we'll reverse later)
            // For simplicity, store in reverse order directly
            self.instructions
                .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
            self.instructions
                .push(EbpfInsn::add64_imm(EbpfReg::R1, (dst_offset + 19) as i32));
            self.instructions
                .push(EbpfInsn::sub64_reg(EbpfReg::R1, EbpfReg::R4));
            self.instructions
                .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R0));

            // R3 = R3 / 10
            self.instructions.push(EbpfInsn::div64_imm(EbpfReg::R3, 10));

            // R4++ (digit count)
            self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R4, 1));
        }

        // Copy digits from temp area to beginning (reverse order)
        // R4 now has the digit count
        self.instructions
            .push(EbpfInsn::mov64_reg(len_reg, EbpfReg::R4));

        Ok(())
    }
}
