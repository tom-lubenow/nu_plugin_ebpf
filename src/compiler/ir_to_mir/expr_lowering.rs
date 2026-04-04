use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::AddressSpace;
use crate::kernel_btf::{
    KernelBtf, TrampolineFieldProjection, TrampolineFieldSelector, TrampolineValueKind,
    TrampolineValueSpec, TypeInfo,
};

impl<'a> HirToMirLowering<'a> {
    pub(super) fn lower_load_literal(
        &mut self,
        dst: RegId,
        lit: &HirLiteral,
    ) -> Result<(), CompileError> {
        let dst_vreg = self.get_vreg(dst);

        match lit {
            HirLiteral::Int(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(*val),
                });
                // Track literal value for constant propagation
                let meta = self.get_or_create_metadata(dst);
                meta.literal_int = Some(*val);
            }

            HirLiteral::Bool(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(if *val { 1 } else { 0 }),
                });
            }

            HirLiteral::String(bytes) => {
                // Warn if string exceeds eBPF limits
                let string_len = bytes.len();
                let max_content_len = MAX_STRING_SIZE.saturating_sub(1);
                if string_len > max_content_len {
                    eprintln!(
                        "Warning: string literal ({} bytes) exceeds eBPF limit of {} bytes and will be truncated",
                        string_len, max_content_len
                    );
                }
                let content_len = bytes.len().min(max_content_len);
                let aligned_len = align_to_eight(content_len + 1).min(MAX_STRING_SIZE).max(16);

                // Allocate stack slot for string buffer (aligned for emit)
                let slot = self
                    .func
                    .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
                self.record_stack_slot_type(
                    slot,
                    MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: aligned_len,
                    },
                );

                // Build literal bytes with null terminator and zero padding
                let mut literal_bytes = vec![0u8; aligned_len];
                literal_bytes[..content_len].copy_from_slice(&bytes[..content_len]);
                // literal_bytes is zero-initialized, so null + padding are already zeroed.

                // Write literal bytes into the buffer at runtime
                let len_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: len_vreg,
                    src: MirValue::Const(0),
                });
                self.emit(MirInst::StringAppend {
                    dst_buffer: slot,
                    dst_len: len_vreg,
                    val: MirValue::Const(0),
                    val_type: StringAppendType::Literal {
                        bytes: literal_bytes,
                    },
                });

                let string_value = std::str::from_utf8(&bytes[..content_len])
                    .ok()
                    .map(|s| s.to_string());

                // Record slot pointer in a vreg
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                // Track the string slot and value
                let meta = self.get_or_create_metadata(dst);
                meta.string_slot = Some(slot);
                meta.string_len_vreg = Some(len_vreg);
                meta.string_len_bound = Some(content_len);
                meta.field_type = Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: aligned_len,
                });
                // Also track the literal string value for record field names
                if let Some(s) = string_value {
                    meta.literal_string = Some(s);
                }
            }

            HirLiteral::CellPath(cell_path) => {
                // Cell paths are metadata-only - they guide field access compilation
                // They don't need a runtime value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Dummy value
                });
                // Track the cell path for use in FollowCellPath
                let meta = self.get_or_create_metadata(dst);
                meta.cell_path = Some((**cell_path).clone());
            }

            HirLiteral::Record { capacity: _ } => {
                // Record allocation - just track that this is a record
                // Actual fields are added via RecordInsert
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Placeholder
                });
                // Initialize empty record fields in metadata
                let meta = self.get_or_create_metadata(dst);
                meta.record_fields = Vec::new();
            }

            HirLiteral::Range {
                start,
                step,
                end,
                inclusion,
            } => {
                // For eBPF bounded loops, we need compile-time known bounds
                let start_val = self
                    .get_metadata(*start)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Range start must be a compile-time known integer for eBPF loops"
                                .into(),
                        )
                    })?;

                // Step can be nothing (default 1) or an explicit integer
                let step_val = self
                    .get_metadata(*step)
                    .and_then(|m| m.literal_int)
                    .unwrap_or(1);

                let end_val = self
                    .get_metadata(*end)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Range end must be a compile-time known integer for eBPF loops".into(),
                        )
                    })?;

                // Validate step is non-zero
                if step_val == 0 {
                    return Err(CompileError::UnsupportedInstruction(
                        "Range step cannot be zero".into(),
                    ));
                }

                // Store range info in metadata for use by Iterate
                let range = BoundedRange {
                    start: start_val,
                    step: step_val,
                    end: end_val,
                    inclusive: *inclusion == RangeInclusion::Inclusive,
                };

                // Set a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(start_val), // Initial value
                });

                let meta = self.get_or_create_metadata(dst);
                meta.bounded_range = Some(range);
            }

            HirLiteral::List { capacity } => {
                // Allocate stack slot for list: [length: u64, elem0, elem1, ...]
                // Due to eBPF 512-byte stack limit, we cap capacity at 60 elements
                // (8 bytes per elem + 8 bytes for length = 488 bytes max)
                const MAX_LIST_CAPACITY: usize = 60;
                let max_len = (*capacity as usize).min(MAX_LIST_CAPACITY);
                let buffer_size = 8 + (max_len * 8); // length + elements

                let slot = self
                    .func
                    .alloc_stack_slot(buffer_size, 8, StackSlotKind::ListBuffer);

                // Emit ListNew to initialize the list buffer
                self.emit(MirInst::ListNew {
                    dst: dst_vreg,
                    buffer: slot,
                    max_len,
                });

                // Track the list buffer in metadata
                let meta = self.get_or_create_metadata(dst);
                meta.list_buffer = Some((slot, max_len));
            }

            HirLiteral::Closure(block_id) => {
                // Track the closure block ID for use in where/each
                // Closures as first-class values (stored in variables, passed around)
                // are not supported, but inline closures for where/each work.
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            HirLiteral::Block(block_id) => {
                // Track block ID same as closure
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            HirLiteral::RowCondition(block_id) => {
                // RowCondition is used by `where` command - same as Closure
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            _ => {
                return Err(CompileError::UnsupportedLiteral);
            }
        }
        Ok(())
    }

    /// Lower BinaryOp instruction
    pub(super) fn lower_binary_op(
        &mut self,
        lhs_dst: RegId,
        op: nu_protocol::ast::Operator,
        rhs: RegId,
    ) -> Result<(), CompileError> {
        use nu_protocol::ast::{Boolean, Comparison, Math, Operator};

        let lhs_vreg = self.get_vreg(lhs_dst);
        let rhs_vreg = self.get_vreg(rhs);

        let mir_op = match op {
            Operator::Math(Math::Add) => BinOpKind::Add,
            Operator::Math(Math::Subtract) => BinOpKind::Sub,
            Operator::Math(Math::Multiply) => BinOpKind::Mul,
            Operator::Math(Math::Divide) => BinOpKind::Div,
            Operator::Math(Math::Modulo) => BinOpKind::Mod,
            Operator::Comparison(Comparison::Equal) => BinOpKind::Eq,
            Operator::Comparison(Comparison::NotEqual) => BinOpKind::Ne,
            Operator::Comparison(Comparison::LessThan) => BinOpKind::Lt,
            Operator::Comparison(Comparison::LessThanOrEqual) => BinOpKind::Le,
            Operator::Comparison(Comparison::GreaterThan) => BinOpKind::Gt,
            Operator::Comparison(Comparison::GreaterThanOrEqual) => BinOpKind::Ge,
            Operator::Bits(nu_protocol::ast::Bits::BitAnd) => BinOpKind::And,
            Operator::Bits(nu_protocol::ast::Bits::BitOr) => BinOpKind::Or,
            Operator::Bits(nu_protocol::ast::Bits::BitXor) => BinOpKind::Xor,
            Operator::Bits(nu_protocol::ast::Bits::ShiftLeft) => BinOpKind::Shl,
            Operator::Bits(nu_protocol::ast::Bits::ShiftRight) => BinOpKind::Shr,
            // Logical and/or - use bitwise ops since comparisons return 0 or 1
            Operator::Boolean(Boolean::And) => BinOpKind::And,
            Operator::Boolean(Boolean::Or) => BinOpKind::Or,
            Operator::Boolean(Boolean::Xor) => BinOpKind::Xor,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Operator {:?} not supported in eBPF",
                    op
                )));
            }
        };

        self.emit(MirInst::BinOp {
            dst: lhs_vreg,
            op: mir_op,
            lhs: MirValue::VReg(lhs_vreg),
            rhs: MirValue::VReg(rhs_vreg),
        });

        Ok(())
    }

    /// Lower Match instruction (used for pattern matching and short-circuit boolean evaluation)
    pub(super) fn lower_match(
        &mut self,
        pattern: &Pattern,
        src: RegId,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        let src_vreg = self.get_vreg(src);

        match pattern {
            Pattern::Value(value) => match value {
                Value::Bool { val, .. } => {
                    if *val {
                        self.terminate(MirInst::Branch {
                            cond: src_vreg,
                            if_true,
                            if_false,
                        });
                    } else {
                        let tmp = self.func.alloc_vreg();
                        self.emit(MirInst::UnaryOp {
                            dst: tmp,
                            op: crate::compiler::mir::UnaryOpKind::Not,
                            src: MirValue::VReg(src_vreg),
                        });
                        self.terminate(MirInst::Branch {
                            cond: tmp,
                            if_true,
                            if_false,
                        });
                    }
                }
                Value::Nothing { .. } => {
                    let cmp_result = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: cmp_result,
                        op: BinOpKind::Eq,
                        lhs: MirValue::VReg(src_vreg),
                        rhs: MirValue::Const(0),
                    });
                    self.terminate(MirInst::Branch {
                        cond: cmp_result,
                        if_true,
                        if_false,
                    });
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Match against value type {:?} not supported in eBPF",
                        value.get_type()
                    )));
                }
            },
            Pattern::Variable(var_id) => {
                self.var_mappings.insert(*var_id, src_vreg);
                self.terminate(MirInst::Jump { target: if_true });
            }
            Pattern::IgnoreValue => {
                self.terminate(MirInst::Jump { target: if_true });
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "Pattern matching not supported in eBPF".into(),
                ));
            }
        }
        Ok(())
    }

    fn ctx_path_member_name(member: &PathMember) -> Result<String, CompileError> {
        match member {
            PathMember::String { val, .. } => Ok(val.clone()),
            PathMember::Int { val, .. } => Ok(format!("arg{}", val)),
        }
    }

    fn ctx_field_from_name(field_name: String) -> Result<CtxField, CompileError> {
        Ok(match field_name.as_str() {
            "pid" => CtxField::Pid,
            "tid" | "tgid" => CtxField::Tid,
            "uid" => CtxField::Uid,
            "gid" => CtxField::Gid,
            "comm" => CtxField::Comm,
            "cpu" => CtxField::Cpu,
            "ktime" | "timestamp" => CtxField::Timestamp,
            "retval" => CtxField::RetVal,
            "kstack" => CtxField::KStack,
            "ustack" => CtxField::UStack,
            s if s.starts_with("arg") => {
                let num: u8 = s[3..].parse().map_err(|_| {
                    CompileError::UnsupportedInstruction(format!("Invalid arg: {}", s))
                })?;
                CtxField::Arg(num)
            }
            _ => CtxField::TracepointField(field_name),
        })
    }

    fn trampoline_field_selector(
        member: &PathMember,
    ) -> Result<TrampolineFieldSelector, CompileError> {
        match member {
            PathMember::String { val, .. } => Ok(TrampolineFieldSelector::Field(val.clone())),
            PathMember::Int { val, .. } => usize::try_from(*val)
                .map(TrampolineFieldSelector::Index)
                .map_err(|_| {
                    CompileError::UnsupportedInstruction(
                        "trampoline array indexing requires a non-negative integer".into(),
                    )
                }),
        }
    }

    fn trampoline_field_path_desc(path: &[TrampolineFieldSelector]) -> String {
        let mut out = String::new();
        for (idx, segment) in path.iter().enumerate() {
            if idx > 0 {
                out.push('.');
            }
            match segment {
                TrampolineFieldSelector::Field(name) => out.push_str(name),
                TrampolineFieldSelector::Index(index) => out.push_str(&index.to_string()),
            }
        }
        out
    }

    fn trampoline_value_spec(
        &self,
        field: &CtxField,
    ) -> Result<Option<TrampolineValueSpec>, CompileError> {
        match (self.probe_ctx, field) {
            (Some(ctx), CtxField::Arg(idx))
                if matches!(
                    ctx.probe_type,
                    EbpfProgramType::Fentry | EbpfProgramType::Fexit
                ) =>
            {
                let spec = KernelBtf::get()
                    .function_trampoline_arg(&ctx.target, *idx as usize)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.arg{} for {}:{}: {}",
                            idx,
                            ctx.probe_type.section_prefix(),
                            ctx.target,
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "ctx.arg{} is not available on {}:{}",
                            idx,
                            ctx.probe_type.section_prefix(),
                            ctx.target
                        ))
                    })?;
                Ok(Some(spec))
            }
            (Some(ctx), CtxField::RetVal) if matches!(ctx.probe_type, EbpfProgramType::Fexit) => {
                let spec = KernelBtf::get()
                    .function_trampoline_ret(&ctx.target)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.retval for fexit:{}: {}",
                            ctx.target, e
                        ))
                    })?
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "ctx.retval is not available on fexit:{} because the target returns void",
                            ctx.target
                        ))
                    })?;
                Ok(Some(spec))
            }
            _ => Ok(None),
        }
    }

    fn projected_trampoline_field_type(type_info: &TypeInfo) -> Option<MirType> {
        match type_info {
            TypeInfo::Int { size, signed } => Some(match (*size, *signed) {
                (1, false) => MirType::U8,
                (1, true) => MirType::I8,
                (2, false) => MirType::U16,
                (2, true) => MirType::I16,
                (4, false) => MirType::U32,
                (4, true) => MirType::I32,
                (8, false) => MirType::U64,
                (8, true) => MirType::I64,
                _ => return None,
            }),
            TypeInfo::Ptr { is_user, .. } => Some(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: if *is_user {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                },
            }),
            TypeInfo::Array { element, len } => {
                if *len == 0 {
                    return None;
                }
                let elem_ty = Self::projected_trampoline_field_type(element)?;
                Some(MirType::Array {
                    elem: Box::new(elem_ty),
                    len: *len,
                })
            }
            TypeInfo::Struct { name, size, fields } => {
                if *size == 0 {
                    return None;
                }
                if fields.is_empty() {
                    return Self::opaque_trampoline_struct_type(name, *size);
                }

                let mut mir_fields = Vec::with_capacity(fields.len() + 1);
                let mut cursor = 0usize;
                let mut pad_index = 0usize;
                for field in fields {
                    if field.offset < cursor {
                        return Self::opaque_trampoline_struct_type(name, *size);
                    }
                    if field.offset > cursor {
                        mir_fields.push(Self::synthetic_padding_field(
                            cursor,
                            field.offset - cursor,
                            pad_index,
                        )?);
                        pad_index += 1;
                    }

                    let field_ty = Self::projected_trampoline_field_type(&field.type_info)
                        .or_else(|| Self::trampoline_byte_array_type(field.size))
                        .filter(|ty| ty.size() == field.size)
                        .or_else(|| Self::trampoline_byte_array_type(field.size))?;
                    mir_fields.push(crate::compiler::mir::StructField {
                        name: field.name.clone(),
                        ty: field_ty,
                        offset: field.offset,
                        synthetic: false,
                    });
                    cursor = field.offset + field.size;
                }
                if cursor > *size {
                    return Self::opaque_trampoline_struct_type(name, *size);
                }
                if cursor < *size {
                    mir_fields.push(Self::synthetic_padding_field(
                        cursor,
                        *size - cursor,
                        pad_index,
                    )?);
                }

                Some(MirType::Struct {
                    name: Some(name.clone()),
                    fields: mir_fields,
                })
            }
            _ => None,
        }
    }

    fn trampoline_byte_array_type(size: usize) -> Option<MirType> {
        if size == 0 {
            return None;
        }
        Some(MirType::Array {
            elem: Box::new(MirType::U8),
            len: size,
        })
    }

    fn opaque_trampoline_struct_type(name: &str, size: usize) -> Option<MirType> {
        Some(MirType::Struct {
            name: Some(name.to_string()),
            fields: vec![crate::compiler::mir::StructField {
                name: "__opaque".to_string(),
                ty: Self::trampoline_byte_array_type(size)?,
                offset: 0,
                synthetic: false,
            }],
        })
    }

    fn synthetic_padding_field(
        offset: usize,
        size: usize,
        pad_index: usize,
    ) -> Option<crate::compiler::mir::StructField> {
        Some(crate::compiler::mir::StructField {
            name: format!("__layout_pad{}", pad_index),
            ty: Self::trampoline_byte_array_type(size)?,
            offset,
            synthetic: true,
        })
    }

    fn trampoline_pointer_type(address_space: AddressSpace) -> MirType {
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space,
        }
    }

    fn scalar_mir_type_for_size(size: usize) -> Result<MirType, CompileError> {
        Ok(match size {
            1 => MirType::U8,
            2 => MirType::U16,
            4 => MirType::U32,
            8 => MirType::U64,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported stack scalar width {}",
                    size
                )));
            }
        })
    }

    fn largest_aligned_stack_chunk(remaining: usize, offsets: &[usize]) -> usize {
        for chunk in [8usize, 4, 2, 1] {
            if remaining >= chunk && offsets.iter().all(|offset| offset % chunk == 0) {
                return chunk;
            }
        }
        1
    }

    fn emit_zero_stack_slot_bytes(
        &mut self,
        slot: StackSlotId,
        size: usize,
    ) -> Result<(), CompileError> {
        let mut written = 0usize;
        while written < size {
            let chunk = Self::largest_aligned_stack_chunk(size - written, &[written]);
            let ty = Self::scalar_mir_type_for_size(chunk)?;
            let offset = i32::try_from(written).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "stack slot zero offset {} is too large",
                    written
                ))
            })?;
            self.emit(MirInst::StoreSlot {
                slot,
                offset,
                val: MirValue::Const(0),
                ty,
            });
            written += chunk;
        }
        Ok(())
    }

    fn trampoline_projection_offset_i32(
        offset_bytes: usize,
        path_desc: &str,
    ) -> Result<i32, CompileError> {
        i32::try_from(offset_bytes).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "projected trampoline field '{}' offset is too large",
                path_desc
            ))
        })
    }

    fn emit_trampoline_probe_read_to_slot(
        &mut self,
        ptr_vreg: VReg,
        address_space: AddressSpace,
        read_offset_bytes: usize,
        slot: StackSlotId,
        slot_ty: &MirType,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let helper = match address_space {
            AddressSpace::Kernel => BpfHelper::ProbeReadKernel as u32,
            AddressSpace::User => BpfHelper::ProbeReadUser as u32,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported trampoline pointer address space for '{}': {:?}",
                    path_desc, address_space
                )));
            }
        };

        self.emit_zero_stack_slot_bytes(slot, slot_ty.size())?;

        let cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: cond_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ptr_vreg),
            rhs: MirValue::Const(0),
        });

        let read_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: read_block,
            if_false: join_block,
        });

        self.current_block = read_block;
        let src_ptr_vreg = if read_offset_bytes == 0 {
            ptr_vreg
        } else {
            let ptr_ty = Self::trampoline_pointer_type(address_space);
            let field_ptr_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(field_ptr_vreg, ptr_ty.clone());
            let field_offset = i64::from(Self::trampoline_projection_offset_i32(
                read_offset_bytes,
                path_desc,
            )?);
            self.emit(MirInst::BinOp {
                dst: field_ptr_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(ptr_vreg),
                rhs: MirValue::Const(field_offset),
            });
            field_ptr_vreg
        };

        let read_status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: read_status_vreg,
            helper,
            args: vec![
                MirValue::StackSlot(slot),
                MirValue::Const(slot_ty.size() as i64),
                MirValue::VReg(src_ptr_vreg),
            ],
        });
        self.terminate(MirInst::Jump { target: join_block });
        self.current_block = join_block;

        Ok(())
    }

    fn lower_trampoline_field_projection(
        &mut self,
        dst_vreg: VReg,
        ctx_field: &CtxField,
        spec: TrampolineValueSpec,
        projection: &TrampolineFieldProjection,
        projected_ty: &MirType,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let projected_by_ref =
            matches!(projected_ty, MirType::Array { .. } | MirType::Struct { .. });

        enum TrampolineCursor {
            Stack {
                base_vreg: VReg,
                base_offset: usize,
            },
            Pointer {
                ptr_vreg: VReg,
                address_space: AddressSpace,
                base_offset: usize,
            },
        }

        let mut cursor = match spec.kind {
            TrampolineValueKind::Aggregate { size_bytes } => {
                let backing_slot =
                    self.func
                        .alloc_stack_slot(align_to_eight(size_bytes), 8, StackSlotKind::Local);
                self.record_stack_slot_type(
                    backing_slot,
                    MirType::Struct {
                        name: None,
                        fields: vec![crate::compiler::mir::StructField {
                            name: "__opaque".to_string(),
                            ty: MirType::Array {
                                elem: Box::new(MirType::U8),
                                len: size_bytes,
                            },
                            offset: 0,
                            synthetic: false,
                        }],
                    },
                );
                let aggregate_vreg = self.func.alloc_vreg();
                self.emit(MirInst::LoadCtxField {
                    dst: aggregate_vreg,
                    field: ctx_field.clone(),
                    slot: Some(backing_slot),
                });
                TrampolineCursor::Stack {
                    base_vreg: aggregate_vreg,
                    base_offset: 0,
                }
            }
            TrampolineValueKind::Pointer { user_space } => {
                let address_space = if user_space {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                };
                let root_ptr_ty = Self::trampoline_pointer_type(address_space);
                let root_ptr_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(root_ptr_vreg, root_ptr_ty);
                self.emit(MirInst::LoadCtxField {
                    dst: root_ptr_vreg,
                    field: ctx_field.clone(),
                    slot: None,
                });
                TrampolineCursor::Pointer {
                    ptr_vreg: root_ptr_vreg,
                    address_space,
                    base_offset: 0,
                }
            }
            TrampolineValueKind::Scalar => {
                return Err(CompileError::UnsupportedInstruction(
                    "nested ctx field access requires a struct/union trampoline value or pointer to one"
                        .into(),
                ));
            }
        };

        for (segment_idx, segment) in projection.path.iter().enumerate() {
            let is_last = segment_idx + 1 == projection.path.len();
            match cursor {
                TrampolineCursor::Stack {
                    base_vreg,
                    base_offset,
                } => {
                    let field_offset =
                        base_offset
                            .checked_add(segment.offset_bytes)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "projected trampoline field '{}' offset overflowed",
                                    path_desc
                                ))
                            })?;

                    if is_last {
                        if projected_by_ref {
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(projected_ty.clone()),
                                    address_space: AddressSpace::Stack,
                                },
                            );
                            if field_offset == 0 {
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::VReg(base_vreg),
                                });
                            } else {
                                self.emit(MirInst::BinOp {
                                    dst: dst_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                            }
                        } else {
                            self.emit(MirInst::Load {
                                dst: dst_vreg,
                                ptr: base_vreg,
                                offset: Self::trampoline_projection_offset_i32(
                                    field_offset,
                                    path_desc,
                                )?,
                                ty: projected_ty.clone(),
                            });
                        }
                        break;
                    }

                    match &segment.type_info {
                        TypeInfo::Struct { .. } | TypeInfo::Array { .. } => {
                            cursor = TrampolineCursor::Stack {
                                base_vreg,
                                base_offset: field_offset,
                            };
                        }
                        TypeInfo::Ptr { is_user, .. } => {
                            let address_space = if *is_user {
                                AddressSpace::User
                            } else {
                                AddressSpace::Kernel
                            };
                            let ptr_ty = Self::trampoline_pointer_type(address_space);
                            let ptr_vreg = self.func.alloc_vreg();
                            self.vreg_type_hints.insert(ptr_vreg, ptr_ty.clone());
                            self.emit(MirInst::Load {
                                dst: ptr_vreg,
                                ptr: base_vreg,
                                offset: Self::trampoline_projection_offset_i32(
                                    field_offset,
                                    path_desc,
                                )?,
                                ty: ptr_ty,
                            });
                            cursor = TrampolineCursor::Pointer {
                                ptr_vreg,
                                address_space,
                                base_offset: 0,
                            };
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "projected trampoline field '{}' requires an aggregate or pointer before the final segment",
                                path_desc
                            )));
                        }
                    }
                }
                TrampolineCursor::Pointer {
                    ptr_vreg,
                    address_space,
                    base_offset,
                } => {
                    let field_offset =
                        base_offset
                            .checked_add(segment.offset_bytes)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "projected trampoline field '{}' offset overflowed",
                                    path_desc
                                ))
                            })?;

                    if is_last {
                        let projected_slot = self.func.alloc_stack_slot(
                            align_to_eight(projected_ty.size()),
                            8,
                            StackSlotKind::Local,
                        );
                        self.record_stack_slot_type(projected_slot, projected_ty.clone());
                        self.emit_trampoline_probe_read_to_slot(
                            ptr_vreg,
                            address_space,
                            field_offset,
                            projected_slot,
                            projected_ty,
                            path_desc,
                        )?;
                        if projected_by_ref {
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(projected_ty.clone()),
                                    address_space: AddressSpace::Stack,
                                },
                            );
                            self.emit(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::StackSlot(projected_slot),
                            });
                        } else {
                            self.emit(MirInst::LoadSlot {
                                dst: dst_vreg,
                                slot: projected_slot,
                                offset: 0,
                                ty: projected_ty.clone(),
                            });
                        }
                        break;
                    }

                    match &segment.type_info {
                        TypeInfo::Struct { .. } | TypeInfo::Array { .. } => {
                            cursor = TrampolineCursor::Pointer {
                                ptr_vreg,
                                address_space,
                                base_offset: field_offset,
                            };
                        }
                        TypeInfo::Ptr { is_user, .. } => {
                            let next_address_space = if *is_user {
                                AddressSpace::User
                            } else {
                                AddressSpace::Kernel
                            };
                            let ptr_ty = Self::trampoline_pointer_type(next_address_space);
                            let pointer_slot = self.func.alloc_stack_slot(
                                align_to_eight(8),
                                8,
                                StackSlotKind::Local,
                            );
                            self.record_stack_slot_type(pointer_slot, ptr_ty.clone());
                            self.emit_trampoline_probe_read_to_slot(
                                ptr_vreg,
                                address_space,
                                field_offset,
                                pointer_slot,
                                &ptr_ty,
                                path_desc,
                            )?;
                            let next_ptr_vreg = self.func.alloc_vreg();
                            self.vreg_type_hints.insert(next_ptr_vreg, ptr_ty.clone());
                            self.emit(MirInst::LoadSlot {
                                dst: next_ptr_vreg,
                                slot: pointer_slot,
                                offset: 0,
                                ty: ptr_ty,
                            });
                            cursor = TrampolineCursor::Pointer {
                                ptr_vreg: next_ptr_vreg,
                                address_space: next_address_space,
                                base_offset: 0,
                            };
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "projected trampoline field '{}' requires an aggregate or pointer before the final segment",
                                path_desc
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Lower FollowCellPath instruction (context field access like $ctx.pid)
    pub(super) fn lower_follow_cell_path(
        &mut self,
        src_dst: RegId,
        path_reg: RegId,
    ) -> Result<(), CompileError> {
        if !self.is_context_reg(src_dst) {
            return Err(CompileError::UnsupportedInstruction(
                "FollowCellPath only supported on context parameter".into(),
            ));
        }

        let path = self
            .get_metadata(path_reg)
            .and_then(|m| m.cell_path.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Cell path literal not found".into())
            })?;
        if path.members.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "Empty cell path is not supported".into(),
            ));
        }

        let field_name = Self::ctx_path_member_name(&path.members[0])?;
        let ctx_field = Self::ctx_field_from_name(field_name)?;
        if let Some(ctx) = self.probe_ctx {
            ctx.validate_ctx_field_access(&ctx_field)?;
        }

        let dst_vreg = self.get_vreg(src_dst);
        let trampoline_value_spec = self.trampoline_value_spec(&ctx_field)?;

        if path.members.len() > 1 {
            let ctx = self.probe_ctx.ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "nested ctx field access requires probe context".into(),
                )
            })?;
            let nested_segments: Vec<TrampolineFieldSelector> = path.members[1..]
                .iter()
                .map(Self::trampoline_field_selector)
                .collect::<Result<_, _>>()?;
            let path_desc = Self::trampoline_field_path_desc(&nested_segments);
            let Some(spec) = trampoline_value_spec else {
                return Err(CompileError::UnsupportedInstruction(
                    "nested ctx field access is only supported for fentry/fexit trampoline args and returns"
                        .into(),
                ));
            };
            if matches!(spec.kind, TrampolineValueKind::Scalar) {
                return Err(CompileError::UnsupportedInstruction(
                    "nested ctx field access requires a struct/union trampoline value or pointer to one"
                        .into(),
                ));
            }
            let projection = match &ctx_field {
                CtxField::Arg(idx) => KernelBtf::get()
                    .function_trampoline_arg_field(&ctx.target, *idx as usize, &nested_segments)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.arg{}.{} for {}:{}: {}",
                            idx,
                            path_desc,
                            ctx.probe_type.section_prefix(),
                            ctx.target,
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "ctx.arg{} is not available on {}:{}",
                            idx,
                            ctx.probe_type.section_prefix(),
                            ctx.target
                        ))
                    })?,
                CtxField::RetVal => KernelBtf::get()
                    .function_trampoline_ret_field(&ctx.target, &nested_segments)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.retval.{} for fexit:{}: {}",
                            path_desc,
                            ctx.target,
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "ctx.retval is not available on fexit:{} because the target returns void",
                            ctx.target
                        ))
                    })?,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(
                        "nested ctx field access is only supported for trampoline args and retval"
                            .into(),
                    ));
                }
            };
            let projected_ty =
                Self::projected_trampoline_field_type(&projection.type_info).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "projected trampoline field '{}' has unsupported type {:?}; only scalar, pointer, and terminal aggregate/array fields are supported",
                        path_desc,
                        projection.type_info
                    ))
                })?;
            self.lower_trampoline_field_projection(
                dst_vreg,
                &ctx_field,
                spec,
                &projection,
                &projected_ty,
                &path_desc,
            )?;

            let projected_ty = projected_ty.clone();
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;
            meta.field_type = Some(projected_ty);
            return Ok(());
        }

        let slot = trampoline_value_spec
            .and_then(|spec| match spec.kind {
                TrampolineValueKind::Aggregate { size_bytes } => Some(self.func.alloc_stack_slot(
                    align_to_eight(size_bytes),
                    8,
                    StackSlotKind::Local,
                )),
                _ => None,
            })
            .or_else(|| self.get_metadata(src_dst).and_then(|m| m.string_slot));
        self.emit(MirInst::LoadCtxField {
            dst: dst_vreg,
            field: ctx_field.clone(),
            slot,
        });

        let field_type = match &ctx_field {
            CtxField::Comm => MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid => MirType::I32,
            _ => match trampoline_value_spec.map(|spec| spec.kind) {
                Some(TrampolineValueKind::Aggregate { size_bytes }) => MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: size_bytes,
                },
                _ => MirType::I64,
            },
        };

        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = false;
        meta.field_type = Some(field_type);

        Ok(())
    }
}
