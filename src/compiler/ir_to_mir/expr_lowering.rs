use super::*;
use crate::compiler::ProgramValueAccess;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::AddressSpace;
use crate::compiler::mir::StructField;
use crate::compiler::mir::UnaryOpKind;
use crate::kernel_btf::{
    KernelBtf, TrampolineBitfieldInfo, TrampolineFieldProjection, TrampolineFieldSelector,
    TrampolineValueKind, TrampolineValueSpec, TypeInfo,
};

#[derive(Debug, Clone)]
struct TypedProjectionStep {
    offset: usize,
    ty: MirType,
    bitfield: Option<TrampolineBitfieldInfo>,
    packet_big_endian: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketPayloadStepKind {
    Ethernet,
    Ipv4,
    Udp,
    Tcp,
}

impl<'a> HirToMirLowering<'a> {
    fn lower_constant_list_value(
        &mut self,
        dst: RegId,
        values: &[Value],
    ) -> Result<(), CompileError> {
        self.lower_load_literal(
            dst,
            &HirLiteral::List {
                capacity: values.len(),
            },
        )?;

        let list_vreg = self.get_vreg(dst);
        for value in values {
            if !crate::compiler::hir::is_numeric_constant_value(value) {
                return Err(CompileError::UnsupportedInstruction(
                    "constant lists currently only support numeric scalar elements in eBPF lowering"
                        .into(),
                ));
            }

            let item_reg = self.alloc_synthetic_reg();
            self.lower_constant_value_with_lists(item_reg, value, false)?;
            let item_vreg = self.get_vreg(item_reg);
            self.emit(MirInst::ListPush {
                list: list_vreg,
                item: item_vreg,
            });
        }

        Ok(())
    }

    fn constant_record_type_from_fields(fields: &[(String, MirType)]) -> MirType {
        let mut offset = 0usize;
        let struct_fields = fields
            .iter()
            .map(|(name, ty)| {
                let struct_field = StructField {
                    name: name.clone(),
                    ty: ty.clone(),
                    offset,
                    synthetic: false,
                    bitfield: None,
                };
                offset = offset.saturating_add(ty.size());
                struct_field
            })
            .collect();
        MirType::Struct {
            name: None,
            kernel_btf_type_id: None,
            fields: struct_fields,
        }
    }

    fn alloc_readonly_global_name(&mut self) -> String {
        let id = self.readonly_global_counter;
        self.readonly_global_counter = self.readonly_global_counter.saturating_add(1);
        format!("__nu_rodata_const_{}", id)
    }

    fn scalar_constant_rodata_repr(value: &Value) -> Option<(MirType, Vec<u8>)> {
        let encoded = match value {
            Value::Bool { val, .. } => Some(if *val { 1i64 } else { 0 }),
            Value::Int { val, .. } => Some(*val),
            Value::Filesize { val, .. } => Some(val.get()),
            Value::Duration { val, .. } => Some(*val),
            Value::Nothing { .. } => Some(0),
            _ => None,
        }?;
        Some((MirType::I64, encoded.to_le_bytes().to_vec()))
    }

    fn string_constant_rodata_repr(value: &Value) -> Option<(MirType, Vec<u8>)> {
        let bytes = match value {
            Value::String { val, .. } => Some(val.as_bytes()),
            Value::Glob { val, .. } => Some(val.as_bytes()),
            _ => None,
        }?;

        let content_len = bytes.len().min(MAX_STRING_SIZE.saturating_sub(1));
        let aligned_len = align_to_eight(content_len + 1).min(MAX_STRING_SIZE).max(16);
        let mut data = vec![0u8; aligned_len];
        data[..content_len].copy_from_slice(&bytes[..content_len]);
        Some((
            MirType::Array {
                elem: Box::new(MirType::U8),
                len: aligned_len,
            },
            data,
        ))
    }

    fn constant_value_rodata_repr(value: &Value) -> Result<(MirType, Vec<u8>), CompileError> {
        if let Some(repr) = Self::scalar_constant_rodata_repr(value) {
            return Ok(repr);
        }
        if let Some(repr) = Self::string_constant_rodata_repr(value) {
            return Ok(repr);
        }

        match value {
            Value::Record { val, .. } => Self::constant_record_rodata_repr(val.as_ref()),
            Value::List { .. } => Err(CompileError::UnsupportedInstruction(
                "constant lists nested inside records are not yet supported in eBPF lowering"
                    .into(),
            )),
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "LoadValue of type {} is not supported in eBPF lowering",
                value.get_type()
            ))),
        }
    }

    fn constant_record_rodata_repr(
        record: &nu_protocol::Record,
    ) -> Result<(MirType, Vec<u8>), CompileError> {
        let mut field_layouts = Vec::with_capacity(record.len());
        let mut data = Vec::new();

        for (field_name, field_value) in record.iter() {
            let (field_ty, field_data) = Self::constant_value_rodata_repr(field_value)?;
            field_layouts.push((field_name.clone(), field_ty));
            data.extend_from_slice(&field_data);
        }

        Ok((Self::constant_record_type_from_fields(&field_layouts), data))
    }

    fn lower_constant_record_value(
        &mut self,
        dst: RegId,
        record: &nu_protocol::Record,
    ) -> Result<(), CompileError> {
        let dst_vreg = if self.reg_map.contains_key(&dst.get()) {
            self.assign_fresh_vreg(dst)
        } else {
            self.get_vreg(dst)
        };
        self.reg_metadata.insert(dst.get(), RegMetadata::default());

        let (record_ty, data) = Self::constant_record_rodata_repr(record)?;
        let symbol = self.alloc_readonly_global_name();
        self.readonly_globals.push(ReadonlyGlobal {
            name: symbol.clone(),
            data,
        });

        let global_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadReadonlyGlobal {
            dst: global_vreg,
            symbol,
            ty: record_ty.clone(),
        });

        let base_runtime_ty = MirType::Ptr {
            pointee: Box::new(record_ty.clone()),
            address_space: AddressSpace::Map,
        };
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::VReg(global_vreg),
        });
        self.vreg_type_hints
            .insert(global_vreg, base_runtime_ty.clone());
        self.vreg_type_hints
            .insert(dst_vreg, base_runtime_ty.clone());

        let mut record_fields = Vec::new();
        let struct_fields = match &record_ty {
            MirType::Struct { fields, .. } => fields.clone(),
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "constant record lowering did not produce a struct layout".into(),
                ));
            }
        };
        for field in struct_fields.into_iter().filter(|field| !field.synthetic) {
            let field_vreg = self.func.alloc_vreg();
            let path = vec![PathMember::string(
                field.name.clone(),
                false,
                Casing::Sensitive,
                Span::unknown(),
            )];
            let field_ty = self.lower_typed_value_projection(
                field_vreg,
                dst_vreg,
                &base_runtime_ty,
                &path,
                &field.name,
            )?;
            record_fields.push(RecordField {
                name: field.name,
                value_vreg: field_vreg,
                stack_offset: None,
                ty: field_ty,
            });
        }

        let meta = self.get_or_create_metadata(dst);
        meta.is_context = false;
        meta.record_fields = record_fields;
        meta.field_type = Some(record_ty);

        Ok(())
    }

    pub(super) fn lower_constant_value(
        &mut self,
        dst: RegId,
        value: &Value,
    ) -> Result<(), CompileError> {
        self.lower_constant_value_with_lists(dst, value, true)
    }

    fn lower_constant_value_with_lists(
        &mut self,
        dst: RegId,
        value: &Value,
        allow_top_level_list: bool,
    ) -> Result<(), CompileError> {
        if let Some(lit) = HirLiteral::from_constant_value(value) {
            return self.lower_load_literal(dst, &lit);
        }

        match value {
            Value::Record { val, .. } => self.lower_constant_record_value(dst, val.as_ref()),
            Value::List { vals, .. } if allow_top_level_list => {
                self.lower_constant_list_value(dst, vals)
            }
            Value::List { .. } => Err(CompileError::UnsupportedInstruction(
                "constant lists nested inside records are not yet supported in eBPF lowering"
                    .into(),
            )),
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "LoadValue of type {} is not supported in eBPF lowering",
                value.get_type()
            ))),
        }
    }

    fn lower_const_i64_literal(&mut self, dst: RegId, dst_vreg: VReg, value: i64) {
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(value),
        });
        let meta = self.get_or_create_metadata(dst);
        meta.literal_int = Some(value);
    }

    fn lower_string_like_literal(
        &mut self,
        dst: RegId,
        dst_vreg: VReg,
        bytes: &[u8],
    ) -> Result<(), CompileError> {
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

        Ok(())
    }

    pub(super) fn lower_load_literal(
        &mut self,
        dst: RegId,
        lit: &HirLiteral,
    ) -> Result<(), CompileError> {
        let dst_vreg = if self.reg_map.contains_key(&dst.get()) {
            self.assign_fresh_vreg(dst)
        } else {
            self.get_vreg(dst)
        };
        self.reg_metadata.insert(dst.get(), RegMetadata::default());

        match lit {
            HirLiteral::Int(val) => {
                self.lower_const_i64_literal(dst, dst_vreg, *val);
            }

            HirLiteral::Bool(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(if *val { 1 } else { 0 }),
                });
            }

            HirLiteral::Filesize(val) => {
                self.lower_const_i64_literal(dst, dst_vreg, val.get());
            }

            HirLiteral::Duration(val) => {
                self.lower_const_i64_literal(dst, dst_vreg, *val);
            }

            HirLiteral::Nothing => {
                // `nothing` is used by Nushell IR for omitted range steps and
                // other optional parser slots. Lower it to a zero placeholder.
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            HirLiteral::String(bytes)
            | HirLiteral::RawString(bytes)
            | HirLiteral::Filepath { val: bytes, .. }
            | HirLiteral::Directory { val: bytes, .. }
            | HirLiteral::GlobPattern { val: bytes, .. } => {
                self.lower_string_like_literal(dst, dst_vreg, bytes)?;
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
                self.record_list_buffer_slot_type(slot, max_len);

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
            "packet_len" | "len" => CtxField::PacketLen,
            "data" => CtxField::Data,
            "data_end" => CtxField::DataEnd,
            "ifindex" | "ingress_ifindex" => CtxField::IngressIfindex,
            "rx_queue_index" => CtxField::RxQueueIndex,
            "egress_ifindex" => CtxField::EgressIfindex,
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

    fn typed_value_path_desc(path: &[PathMember]) -> String {
        let mut out = String::new();
        for (idx, member) in path.iter().enumerate() {
            if idx > 0 {
                out.push('.');
            }
            match member {
                PathMember::String { val, .. } => out.push_str(val),
                PathMember::Int { val, .. } => out.push_str(&val.to_string()),
            }
        }
        out
    }

    pub(super) fn typed_value_runtime_type(&self, reg: RegId, vreg: VReg) -> Option<MirType> {
        self.vreg_type_hints
            .get(&vreg)
            .cloned()
            .or_else(|| self.current_type_hints.get(&reg.get()).cloned())
            .or_else(|| self.get_metadata(reg).and_then(|m| m.field_type.clone()))
    }

    fn trampoline_value_spec(
        &self,
        field: &CtxField,
    ) -> Result<Option<TrampolineValueSpec>, CompileError> {
        match (self.probe_ctx, field) {
            (Some(ctx), CtxField::Arg(idx)) if ctx.probe_type.uses_btf_trampoline() => {
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
            (Some(ctx), CtxField::RetVal)
                if matches!(
                    ctx.probe_type.retval_access(),
                    ProgramValueAccess::Trampoline
                ) =>
            {
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
            TypeInfo::Ptr {
                target, is_user, ..
            } => Some(MirType::Ptr {
                pointee: Box::new(
                    Self::projected_trampoline_field_type(target).unwrap_or(MirType::U8),
                ),
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
            TypeInfo::Struct {
                name,
                btf_type_id,
                size,
                fields,
            } => {
                if *size == 0 {
                    return None;
                }
                if fields.is_empty() {
                    return Self::opaque_trampoline_struct_type(name, *size, *btf_type_id);
                }

                let mut mir_fields = Vec::with_capacity(fields.len() + 1);
                let mut cursor = 0usize;
                let mut pad_index = 0usize;
                for field in fields {
                    if field.size == 0 || field.offset >= *size {
                        continue;
                    }
                    if field.offset < cursor && field.bitfield.is_none() {
                        continue;
                    }
                    if field.offset > cursor {
                        mir_fields.push(Self::synthetic_padding_field(
                            cursor,
                            field.offset - cursor,
                            pad_index,
                        )?);
                        pad_index += 1;
                    }

                    let Some(field_ty) = Self::projected_trampoline_field_type(&field.type_info)
                        .or_else(|| Self::trampoline_byte_array_type(field.size))
                        .filter(|ty| ty.size() == field.size)
                        .or_else(|| Self::trampoline_byte_array_type(field.size))
                    else {
                        continue;
                    };
                    let Some(field_end) = field.offset.checked_add(field.size) else {
                        continue;
                    };
                    if field_end > *size {
                        continue;
                    }
                    mir_fields.push(crate::compiler::mir::StructField {
                        name: field.name.clone(),
                        ty: field_ty,
                        offset: field.offset,
                        synthetic: false,
                        bitfield: field.bitfield.map(|bitfield| {
                            crate::compiler::mir::BitfieldInfo {
                                bit_offset: bitfield.bit_offset,
                                bit_size: bitfield.bit_size,
                            }
                        }),
                    });
                    cursor = cursor.max(field_end);
                }
                if mir_fields.is_empty() {
                    return Self::opaque_trampoline_struct_type(name, *size, *btf_type_id);
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
                    kernel_btf_type_id: *btf_type_id,
                    fields: mir_fields,
                })
            }
            _ => None,
        }
    }

    fn mir_type_is_signed(ty: &MirType) -> bool {
        matches!(ty, MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64)
    }

    fn large_const_operand(&mut self, ty: &MirType, value: i64) -> MirValue {
        if i32::try_from(value).is_ok() {
            return MirValue::Const(value);
        }

        let const_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(const_vreg, ty.clone());
        self.emit(MirInst::Copy {
            dst: const_vreg,
            src: MirValue::Const(value),
        });
        MirValue::VReg(const_vreg)
    }

    fn emit_bitfield_extract(
        &mut self,
        dst_vreg: VReg,
        loaded_vreg: VReg,
        projected_ty: &MirType,
        bitfield: TrampolineBitfieldInfo,
    ) -> Result<(), CompileError> {
        let storage_bits = u32::try_from(projected_ty.size().checked_mul(8).ok_or_else(|| {
            CompileError::UnsupportedInstruction("bitfield extraction size overflowed".to_string())
        })?)
        .map_err(|_| {
            CompileError::UnsupportedInstruction("bitfield extraction size overflowed".to_string())
        })?;
        if bitfield.bit_size == 0 || bitfield.bit_size > storage_bits {
            return Err(CompileError::UnsupportedInstruction(format!(
                "unsupported {}-bit bitfield extraction from {:?}",
                bitfield.bit_size, projected_ty
            )));
        }
        let bitfield_end = bitfield
            .bit_offset
            .checked_add(bitfield.bit_size)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("bitfield extraction overflowed".to_string())
            })?;
        if bitfield_end > storage_bits {
            return Err(CompileError::UnsupportedInstruction(format!(
                "bitfield extraction exceeds {:?} storage width",
                projected_ty
            )));
        }

        let mut current_vreg = loaded_vreg;
        if bitfield.bit_offset > 0 {
            let shifted_vreg = self.func.alloc_vreg();
            self.vreg_type_hints
                .insert(shifted_vreg, projected_ty.clone());
            let shift_amount =
                self.large_const_operand(projected_ty, i64::from(bitfield.bit_offset));
            self.emit(MirInst::BinOp {
                dst: shifted_vreg,
                op: BinOpKind::Shr,
                lhs: MirValue::VReg(current_vreg),
                rhs: shift_amount,
            });
            current_vreg = shifted_vreg;
        }

        if bitfield.bit_size < storage_bits {
            let masked_vreg = self.func.alloc_vreg();
            self.vreg_type_hints
                .insert(masked_vreg, projected_ty.clone());
            let mask = ((1u128 << bitfield.bit_size) - 1) as i64;
            let mask_value = self.large_const_operand(projected_ty, mask);
            self.emit(MirInst::BinOp {
                dst: masked_vreg,
                op: BinOpKind::And,
                lhs: MirValue::VReg(current_vreg),
                rhs: mask_value,
            });
            current_vreg = masked_vreg;
        }

        if Self::mir_type_is_signed(projected_ty) && bitfield.bit_size < storage_bits {
            let sign_bit = 1i64.checked_shl(bitfield.bit_size - 1).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "bitfield sign extension overflowed".to_string(),
                )
            })?;
            let xor_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(xor_vreg, projected_ty.clone());
            let sign_bit_value = self.large_const_operand(projected_ty, sign_bit);
            self.emit(MirInst::BinOp {
                dst: xor_vreg,
                op: BinOpKind::Xor,
                lhs: MirValue::VReg(current_vreg),
                rhs: sign_bit_value,
            });

            let signed_vreg = self.func.alloc_vreg();
            self.vreg_type_hints
                .insert(signed_vreg, projected_ty.clone());
            let sign_bit_value = self.large_const_operand(projected_ty, sign_bit);
            self.emit(MirInst::BinOp {
                dst: signed_vreg,
                op: BinOpKind::Sub,
                lhs: MirValue::VReg(xor_vreg),
                rhs: sign_bit_value,
            });
            current_vreg = signed_vreg;
        }

        self.vreg_type_hints.insert(dst_vreg, projected_ty.clone());
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::VReg(current_vreg),
        });
        Ok(())
    }

    fn trampoline_root_type_info(
        &self,
        field: &CtxField,
    ) -> Result<Option<TypeInfo>, CompileError> {
        match (self.probe_ctx, field) {
            (Some(ctx), CtxField::Arg(idx)) if ctx.probe_type.uses_btf_trampoline() => {
                KernelBtf::get()
                    .function_trampoline_arg_type_info(&ctx.target, *idx as usize)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.arg{} type for {}:{}: {}",
                            idx,
                            ctx.probe_type.section_prefix(),
                            ctx.target,
                            e
                        ))
                    })
            }
            (Some(ctx), CtxField::RetVal)
                if matches!(
                    ctx.probe_type.retval_access(),
                    ProgramValueAccess::Trampoline
                ) =>
            {
                KernelBtf::get()
                    .function_trampoline_ret_type_info(&ctx.target)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.retval type for fexit:{}: {}",
                            ctx.target, e
                        ))
                    })
            }
            _ => Ok(None),
        }
    }

    fn root_trampoline_value_types(
        type_info: &TypeInfo,
        kind: TrampolineValueKind,
    ) -> Option<(MirType, MirType)> {
        match kind {
            TrampolineValueKind::Scalar => {
                let ty = Self::projected_trampoline_field_type(type_info).unwrap_or(MirType::I64);
                Some((ty.clone(), ty))
            }
            TrampolineValueKind::Pointer { user_space } => {
                let address_space = if user_space {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                };
                let runtime_ty = Self::projected_trampoline_field_type(type_info)
                    .unwrap_or_else(|| Self::trampoline_pointer_type(address_space));
                Some((runtime_ty.clone(), runtime_ty))
            }
            TrampolineValueKind::Aggregate { size_bytes } => {
                let semantic_ty = Self::projected_trampoline_field_type(type_info)
                    .or_else(|| Self::trampoline_byte_array_type(size_bytes))?;
                let runtime_ty = MirType::Ptr {
                    pointee: Box::new(semantic_ty.clone()),
                    address_space: AddressSpace::Stack,
                };
                Some((semantic_ty, runtime_ty))
            }
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

    fn opaque_trampoline_struct_type(
        name: &str,
        size: usize,
        kernel_btf_type_id: Option<u32>,
    ) -> Option<MirType> {
        Some(MirType::Struct {
            name: Some(name.to_string()),
            kernel_btf_type_id,
            fields: vec![crate::compiler::mir::StructField {
                name: "__opaque".to_string(),
                ty: Self::trampoline_byte_array_type(size)?,
                offset: 0,
                synthetic: false,
                bitfield: None,
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
            bitfield: None,
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
            let ptr_ty = self
                .vreg_type_hints
                .get(&ptr_vreg)
                .cloned()
                .unwrap_or_else(|| Self::trampoline_pointer_type(address_space));
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

    fn emit_xdp_packet_guarded_load(
        &mut self,
        dst_vreg: VReg,
        packet_ptr_vreg: VReg,
        load_ty: &MirType,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        if matches!(
            load_ty,
            MirType::Array { .. }
                | MirType::Struct { .. }
                | MirType::Ptr { .. }
                | MirType::MapRef { .. }
                | MirType::Unknown
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "xdp packet load for '{}' requires a scalar element type, got {:?}",
                path_desc, load_ty
            )));
        }

        let access_size = i64::try_from(load_ty.size()).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "xdp packet load for '{}' has unsupported size {}",
                path_desc,
                load_ty.size()
            ))
        })?;
        if access_size <= 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "xdp packet load for '{}' requires positive size",
                path_desc
            )));
        }

        self.vreg_type_hints.insert(dst_vreg, load_ty.clone());
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });

        let packet_ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        };
        let data_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(data_end_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: data_end_vreg,
            field: CtxField::DataEnd,
            slot: None,
        });

        let access_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(access_end_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::BinOp {
            dst: access_end_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(packet_ptr_vreg),
            rhs: MirValue::Const(access_size),
        });

        let cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: cond_vreg,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(access_end_vreg),
            rhs: MirValue::VReg(data_end_vreg),
        });

        let load_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: load_block,
            if_false: join_block,
        });

        self.current_block = load_block;
        self.emit(MirInst::Load {
            dst: dst_vreg,
            ptr: packet_ptr_vreg,
            offset: 0,
            ty: load_ty.clone(),
        });
        self.terminate(MirInst::Jump { target: join_block });

        self.current_block = join_block;
        Ok(())
    }

    fn packet_load_ptr_vreg(
        &mut self,
        packet_ptr_vreg: VReg,
        packet_ptr_ty: MirType,
        dst_vreg: VReg,
    ) -> VReg {
        if packet_ptr_vreg != dst_vreg {
            return packet_ptr_vreg;
        }

        let preserved_ptr_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(preserved_ptr_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::Copy {
            dst: preserved_ptr_vreg,
            src: MirValue::VReg(packet_ptr_vreg),
        });
        preserved_ptr_vreg
    }

    fn lower_trampoline_field_projection(
        &mut self,
        dst_vreg: VReg,
        ctx_field: &CtxField,
        spec: TrampolineValueSpec,
        projection: &TrampolineFieldProjection,
        root_runtime_ty: &MirType,
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
                if let MirType::Ptr {
                    pointee,
                    address_space: AddressSpace::Stack,
                } = root_runtime_ty
                {
                    self.record_stack_slot_type(backing_slot, pointee.as_ref().clone());
                } else {
                    self.record_stack_slot_type(
                        backing_slot,
                        MirType::Struct {
                            name: None,
                            kernel_btf_type_id: None,
                            fields: vec![crate::compiler::mir::StructField {
                                name: "__opaque".to_string(),
                                ty: MirType::Array {
                                    elem: Box::new(MirType::U8),
                                    len: size_bytes,
                                },
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        },
                    );
                }
                let aggregate_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(aggregate_vreg, root_runtime_ty.clone());
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
                let root_ptr_ty = match root_runtime_ty {
                    MirType::Ptr { .. } => root_runtime_ty.clone(),
                    _ => Self::trampoline_pointer_type(address_space),
                };
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
                            let loaded_vreg = if segment.bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints
                                    .insert(storage_vreg, projected_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: storage_vreg,
                                    ptr: base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: projected_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = segment.bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    projected_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, projected_ty.clone());
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
                            let loaded_vreg = if segment.bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints
                                    .insert(storage_vreg, projected_ty.clone());
                                self.emit(MirInst::LoadSlot {
                                    dst: storage_vreg,
                                    slot: projected_slot,
                                    offset: 0,
                                    ty: projected_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = segment.bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    projected_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, projected_ty.clone());
                                self.emit(MirInst::LoadSlot {
                                    dst: dst_vreg,
                                    slot: projected_slot,
                                    offset: 0,
                                    ty: projected_ty.clone(),
                                });
                            }
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

    fn resolve_kernel_btf_struct_field_step(
        type_id: u32,
        field_name: &str,
        path_desc: &str,
    ) -> Result<TypedProjectionStep, CompileError> {
        let projection = KernelBtf::get()
            .kernel_type_field_projection(
                type_id,
                &[TrampolineFieldSelector::Field(field_name.to_string())],
            )
            .map_err(|e| {
                CompileError::UnsupportedInstruction(format!(
                    "failed to resolve typed field path '{}' from kernel BTF: {}",
                    path_desc, e
                ))
            })?;
        let offset = projection
            .path
            .first()
            .map(|segment| segment.offset_bytes)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "failed to resolve typed field path '{}' from kernel BTF",
                    path_desc
                ))
            })?;
        let projected_ty = Self::projected_trampoline_field_type(&projection.type_info)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' resolved to unsupported kernel type {:?}",
                    path_desc, projection.type_info
                ))
            })?;
        Ok(TypedProjectionStep {
            offset,
            ty: projected_ty,
            bitfield: projection.path[0].bitfield,
            packet_big_endian: false,
        })
    }

    fn packet_struct_field(
        name: &str,
        ty: MirType,
        offset: usize,
    ) -> crate::compiler::mir::StructField {
        crate::compiler::mir::StructField {
            name: name.to_string(),
            ty,
            offset,
            synthetic: false,
            bitfield: None,
        }
    }

    fn packet_bytes(len: usize) -> MirType {
        MirType::Array {
            elem: Box::new(MirType::U8),
            len,
        }
    }

    fn packet_eth_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_eth".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("dst", Self::packet_bytes(6), 0),
                Self::packet_struct_field("src", Self::packet_bytes(6), 6),
                Self::packet_struct_field("ethertype", MirType::U16, 12),
            ],
        }
    }

    fn packet_ipv4_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_ipv4".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("version_ihl", MirType::U8, 0),
                Self::packet_struct_field("dscp_ecn", MirType::U8, 1),
                Self::packet_struct_field("total_len", MirType::U16, 2),
                Self::packet_struct_field("identification", MirType::U16, 4),
                Self::packet_struct_field("flags_fragment_offset", MirType::U16, 6),
                Self::packet_struct_field("ttl", MirType::U8, 8),
                Self::packet_struct_field("protocol", MirType::U8, 9),
                Self::packet_struct_field("checksum", MirType::U16, 10),
                Self::packet_struct_field("src", Self::packet_bytes(4), 12),
                Self::packet_struct_field("dst", Self::packet_bytes(4), 16),
            ],
        }
    }

    fn packet_udp_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_udp".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("src", MirType::U16, 0),
                Self::packet_struct_field("dst", MirType::U16, 2),
                Self::packet_struct_field("len", MirType::U16, 4),
                Self::packet_struct_field("checksum", MirType::U16, 6),
            ],
        }
    }

    fn packet_tcp_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_tcp".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("src", MirType::U16, 0),
                Self::packet_struct_field("dst", MirType::U16, 2),
                Self::packet_struct_field("seq", MirType::U32, 4),
                Self::packet_struct_field("ack_seq", MirType::U32, 8),
                Self::packet_struct_field("data_offset_flags", MirType::U16, 12),
                Self::packet_struct_field("window", MirType::U16, 14),
                Self::packet_struct_field("checksum", MirType::U16, 16),
                Self::packet_struct_field("urg_ptr", MirType::U16, 18),
            ],
        }
    }

    fn packet_header_view_spec(
        current_ty: &MirType,
        member: &PathMember,
    ) -> Option<TypedProjectionStep> {
        let PathMember::String { val, .. } = member else {
            return None;
        };

        let current_name = match current_ty {
            MirType::Struct { name, .. } => name.as_deref(),
            _ => None,
        };
        let is_raw_packet = matches!(current_ty, MirType::U8);

        match (current_name, is_raw_packet, val.as_str()) {
            (_, true, "eth" | "ethhdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_eth_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "ipv4" | "iphdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_ipv4_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "udp" | "udphdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_udp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "tcp" | "tcphdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_tcp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_eth"), _, "ipv4" | "iphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_ipv4_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_ipv4"), _, "udp" | "udphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_udp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_ipv4"), _, "tcp" | "tcphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_tcp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            _ => None,
        }
    }

    fn packet_payload_step_kind(
        current_ty: &MirType,
        member: &PathMember,
    ) -> Option<PacketPayloadStepKind> {
        let PathMember::String { val, .. } = member else {
            return None;
        };
        if val != "payload" {
            return None;
        }

        match current_ty {
            MirType::Struct {
                name: Some(name), ..
            } => match name.as_str() {
                "__packet_eth" => Some(PacketPayloadStepKind::Ethernet),
                "__packet_ipv4" => Some(PacketPayloadStepKind::Ipv4),
                "__packet_udp" => Some(PacketPayloadStepKind::Udp),
                "__packet_tcp" => Some(PacketPayloadStepKind::Tcp),
                _ => None,
            },
            _ => None,
        }
    }

    fn packet_field_is_big_endian(current_ty: &MirType, member: &PathMember) -> bool {
        let MirType::Struct {
            name: Some(name), ..
        } = current_ty
        else {
            return false;
        };
        let PathMember::String { val, .. } = member else {
            return false;
        };

        match (name.as_str(), val.as_str()) {
            ("__packet_eth", "ethertype") => true,
            (
                "__packet_ipv4",
                "total_len" | "identification" | "flags_fragment_offset" | "checksum",
            ) => true,
            ("__packet_udp", "src" | "dst" | "len" | "checksum") => true,
            (
                "__packet_tcp",
                "src" | "dst" | "seq" | "ack_seq" | "data_offset_flags" | "window" | "checksum"
                | "urg_ptr",
            ) => true,
            _ => false,
        }
    }

    fn resolve_typed_value_projection_step(
        current_ty: &MirType,
        member: &PathMember,
        path_desc: &str,
    ) -> Result<TypedProjectionStep, CompileError> {
        match (current_ty, member) {
            (
                MirType::Struct {
                    fields,
                    kernel_btf_type_id,
                    ..
                },
                PathMember::String { val, .. },
            ) => {
                let field = fields
                    .iter()
                    .find(|field| !field.synthetic && field.name == *val)
                    .map(|field| TypedProjectionStep {
                        offset: field.offset,
                        ty: field.ty.clone(),
                        bitfield: field.bitfield.map(|bitfield| TrampolineBitfieldInfo {
                            bit_offset: bitfield.bit_offset,
                            bit_size: bitfield.bit_size,
                        }),
                        packet_big_endian: Self::packet_field_is_big_endian(current_ty, member),
                    });
                if let Some(field) = field {
                    return Ok(field);
                }
                if let Some(type_id) = *kernel_btf_type_id {
                    return Self::resolve_kernel_btf_struct_field_step(type_id, val, path_desc);
                }
                Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' has no field '{}'",
                    path_desc, val
                )))
            }
            (MirType::Struct { .. }, PathMember::Int { val, .. }) => {
                Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' cannot index {} on a struct",
                    path_desc, val
                )))
            }
            (MirType::Array { elem, len }, PathMember::Int { val, .. }) => {
                let index = usize::try_from(*val).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' requires a non-negative array index",
                        path_desc
                    ))
                })?;
                if index >= *len {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' index {} is out of bounds (len {})",
                        path_desc, index, len
                    )));
                }
                Ok(TypedProjectionStep {
                    offset: index * elem.size(),
                    ty: elem.as_ref().clone(),
                    bitfield: None,
                    packet_big_endian: false,
                })
            }
            (MirType::Array { .. }, PathMember::String { val, .. }) => {
                Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' cannot access field '{}' on an array; use a numeric index",
                    path_desc, val
                )))
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "typed field path '{}' requires an aggregate or pointer to one, got {:?}",
                path_desc, current_ty
            ))),
        }
    }

    fn resolve_pointer_sequence_index_step(
        current_ty: &MirType,
        index: usize,
        path_desc: &str,
    ) -> Result<TypedProjectionStep, CompileError> {
        let offset = index.checked_mul(current_ty.size()).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "typed field path '{}' pointer index {} overflowed",
                path_desc, index
            ))
        })?;
        Ok(TypedProjectionStep {
            offset,
            ty: current_ty.clone(),
            bitfield: None,
            packet_big_endian: false,
        })
    }

    fn packet_scalar_view_spec(member: &PathMember) -> Option<(MirType, usize, bool)> {
        let PathMember::String { val, .. } = member else {
            return None;
        };
        match val.as_str() {
            "u16be" => Some((MirType::U16, 2, true)),
            "u32be" => Some((MirType::U32, 4, true)),
            _ => None,
        }
    }

    fn emit_packet_scalar_load_at_offset(
        &mut self,
        dst_vreg: VReg,
        base_vreg: VReg,
        base_offset: usize,
        load_ty: &MirType,
        big_endian: bool,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let packet_ptr_vreg = if base_offset == 0 {
            base_vreg
        } else {
            let ptr_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(
                ptr_vreg,
                MirType::Ptr {
                    pointee: Box::new(load_ty.clone()),
                    address_space: AddressSpace::Packet,
                },
            );
            self.emit(MirInst::BinOp {
                dst: ptr_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(base_vreg),
                rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                    base_offset,
                    path_desc,
                )?)),
            });
            ptr_vreg
        };
        let packet_ptr_vreg = self.packet_load_ptr_vreg(
            packet_ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(load_ty.clone()),
                address_space: AddressSpace::Packet,
            },
            dst_vreg,
        );
        self.emit_xdp_packet_guarded_load(dst_vreg, packet_ptr_vreg, load_ty, path_desc)?;
        if big_endian {
            self.emit_packet_big_endian_scalar_normalize(dst_vreg, load_ty)?;
        }
        Ok(())
    }

    fn emit_normalize_boolean_vreg(&mut self, dst_vreg: VReg, src_vreg: VReg) {
        let not_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(not_vreg, MirType::Bool);
        self.emit(MirInst::UnaryOp {
            dst: not_vreg,
            op: UnaryOpKind::Not,
            src: MirValue::VReg(src_vreg),
        });

        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.emit(MirInst::UnaryOp {
            dst: dst_vreg,
            op: UnaryOpKind::Not,
            src: MirValue::VReg(not_vreg),
        });
    }

    fn emit_packet_payload_ptr_step(
        &mut self,
        base_vreg: VReg,
        base_offset: usize,
        kind: PacketPayloadStepKind,
        path_desc: &str,
    ) -> Result<VReg, CompileError> {
        let base_ptr_vreg = if base_offset == 0 {
            base_vreg
        } else {
            let ptr_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(
                ptr_vreg,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Packet,
                },
            );
            self.emit(MirInst::BinOp {
                dst: ptr_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(base_vreg),
                rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                    base_offset,
                    path_desc,
                )?)),
            });
            ptr_vreg
        };

        let payload_ptr_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(
            payload_ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Packet,
            },
        );

        match kind {
            PacketPayloadStepKind::Ethernet => {
                let ethertype_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(ethertype_vreg, MirType::U16);
                self.emit_packet_scalar_load_at_offset(
                    ethertype_vreg,
                    base_ptr_vreg,
                    12,
                    &MirType::U16,
                    true,
                    path_desc,
                )?;

                let vlan_8021q = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: vlan_8021q,
                    op: BinOpKind::Eq,
                    lhs: MirValue::VReg(ethertype_vreg),
                    rhs: MirValue::Const(0x8100),
                });
                self.emit_normalize_boolean_vreg(vlan_8021q, vlan_8021q);
                let vlan_8021ad = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: vlan_8021ad,
                    op: BinOpKind::Eq,
                    lhs: MirValue::VReg(ethertype_vreg),
                    rhs: MirValue::Const(0x88a8),
                });
                self.emit_normalize_boolean_vreg(vlan_8021ad, vlan_8021ad);
                let vlan_9100 = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: vlan_9100,
                    op: BinOpKind::Eq,
                    lhs: MirValue::VReg(ethertype_vreg),
                    rhs: MirValue::Const(0x9100),
                });
                self.emit_normalize_boolean_vreg(vlan_9100, vlan_9100);

                let vlan_present = self.func.alloc_vreg();
                self.vreg_type_hints.insert(vlan_present, MirType::Bool);
                self.emit(MirInst::BinOp {
                    dst: vlan_present,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(vlan_8021q),
                    rhs: MirValue::VReg(vlan_8021ad),
                });
                self.emit_normalize_boolean_vreg(vlan_present, vlan_present);
                self.emit(MirInst::BinOp {
                    dst: vlan_present,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(vlan_present),
                    rhs: MirValue::VReg(vlan_9100),
                });
                self.emit_normalize_boolean_vreg(vlan_present, vlan_present);

                let vlan_bytes_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(vlan_bytes_vreg, MirType::U64);
                self.emit(MirInst::BinOp {
                    dst: vlan_bytes_vreg,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(vlan_present),
                    rhs: MirValue::Const(2),
                });

                let eth_payload_base_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(
                    eth_payload_base_vreg,
                    MirType::Ptr {
                        pointee: Box::new(MirType::U8),
                        address_space: AddressSpace::Packet,
                    },
                );
                self.emit(MirInst::BinOp {
                    dst: eth_payload_base_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::Const(14),
                });
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(eth_payload_base_vreg),
                    rhs: MirValue::VReg(vlan_bytes_vreg),
                });
            }
            PacketPayloadStepKind::Ipv4 => {
                let version_ihl_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(version_ihl_vreg, MirType::U8);
                self.emit_packet_scalar_load_at_offset(
                    version_ihl_vreg,
                    base_ptr_vreg,
                    0,
                    &MirType::U8,
                    false,
                    path_desc,
                )?;

                let ihl_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(ihl_vreg, MirType::U64);
                self.emit(MirInst::BinOp {
                    dst: ihl_vreg,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(version_ihl_vreg),
                    rhs: MirValue::Const(0x0f),
                });
                self.emit(MirInst::BinOp {
                    dst: ihl_vreg,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(ihl_vreg),
                    rhs: MirValue::Const(2),
                });
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::VReg(ihl_vreg),
                });
            }
            PacketPayloadStepKind::Udp => {
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::Const(8),
                });
            }
            PacketPayloadStepKind::Tcp => {
                let data_offset_flags_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(data_offset_flags_vreg, MirType::U16);
                self.emit_packet_scalar_load_at_offset(
                    data_offset_flags_vreg,
                    base_ptr_vreg,
                    12,
                    &MirType::U16,
                    true,
                    path_desc,
                )?;

                let data_offset_words_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(data_offset_words_vreg, MirType::U64);
                self.emit(MirInst::BinOp {
                    dst: data_offset_words_vreg,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(data_offset_flags_vreg),
                    rhs: MirValue::Const(12),
                });
                self.emit(MirInst::BinOp {
                    dst: data_offset_words_vreg,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(data_offset_words_vreg),
                    rhs: MirValue::Const(2),
                });
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::VReg(data_offset_words_vreg),
                });
            }
        }

        Ok(payload_ptr_vreg)
    }

    fn emit_packet_big_endian_scalar_normalize(
        &mut self,
        dst_vreg: VReg,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let hint = ty.clone();
        match ty {
            MirType::U16 => {
                let mask_ff = self.large_const_operand(ty, 0xff);
                let shift_8 = self.large_const_operand(ty, 8);
                let low = self.func.alloc_vreg();
                self.vreg_type_hints.insert(low, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: low,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff.clone(),
                });

                let low_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(low_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: low_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(low),
                    rhs: shift_8.clone(),
                });

                let high = self.func.alloc_vreg();
                self.vreg_type_hints.insert(high, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: high,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_8,
                });

                let high_masked = self.func.alloc_vreg();
                self.vreg_type_hints.insert(high_masked, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: high_masked,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(high),
                    rhs: mask_ff,
                });

                self.vreg_type_hints.insert(dst_vreg, hint);
                self.emit(MirInst::BinOp {
                    dst: dst_vreg,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(low_shifted),
                    rhs: MirValue::VReg(high_masked),
                });
                Ok(())
            }
            MirType::U32 => {
                let mask_ff = self.large_const_operand(ty, 0x0000_00ff);
                let mask_ff00 = self.large_const_operand(ty, 0x0000_ff00);
                let shift_8 = self.large_const_operand(ty, 8);
                let shift_24 = self.large_const_operand(ty, 24);
                let b0 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b0, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b0,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff.clone(),
                });
                let b0_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b0_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b0_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(b0),
                    rhs: shift_24.clone(),
                });

                let b1 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b1, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b1,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff00.clone(),
                });
                let b1_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b1_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b1_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(b1),
                    rhs: shift_8.clone(),
                });

                let b2_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b2_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b2_shifted,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_8.clone(),
                });
                let b2 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b2, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b2,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(b2_shifted),
                    rhs: mask_ff00,
                });

                let b3_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b3_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b3_shifted,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_24,
                });
                let b3 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b3, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b3,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(b3_shifted),
                    rhs: mask_ff,
                });

                let hi = self.func.alloc_vreg();
                self.vreg_type_hints.insert(hi, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: hi,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(b0_shifted),
                    rhs: MirValue::VReg(b1_shifted),
                });
                let lo = self.func.alloc_vreg();
                self.vreg_type_hints.insert(lo, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: lo,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(b2),
                    rhs: MirValue::VReg(b3),
                });

                self.vreg_type_hints.insert(dst_vreg, hint);
                self.emit(MirInst::BinOp {
                    dst: dst_vreg,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(hi),
                    rhs: MirValue::VReg(lo),
                });
                Ok(())
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "big-endian packet scalar normalization is not supported for {:?}",
                ty
            ))),
        }
    }

    fn lower_typed_value_projection(
        &mut self,
        dst_vreg: VReg,
        base_vreg: VReg,
        base_runtime_ty: &MirType,
        path_members: &[PathMember],
        path_desc: &str,
    ) -> Result<MirType, CompileError> {
        let projected_by_ref =
            |ty: &MirType| matches!(ty, MirType::Array { .. } | MirType::Struct { .. });

        enum ValueCursor {
            Pointer {
                base_vreg: VReg,
                address_space: AddressSpace,
                base_offset: usize,
                target_ty: MirType,
                direct: bool,
            },
            PacketScalar {
                base_vreg: VReg,
                base_offset: usize,
                element_ty: MirType,
                element_size: usize,
                big_endian: bool,
            },
        }

        let mut cursor = match base_runtime_ty {
            MirType::Ptr {
                pointee,
                address_space,
            } => ValueCursor::Pointer {
                base_vreg,
                address_space: *address_space,
                base_offset: 0,
                target_ty: pointee.as_ref().clone(),
                direct: true,
            },
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' requires a typed pointer value, got {:?}",
                    path_desc, base_runtime_ty
                )));
            }
        };

        for (segment_idx, member) in path_members.iter().enumerate() {
            let is_last = segment_idx + 1 == path_members.len();
            if let ValueCursor::PacketScalar {
                base_vreg,
                base_offset,
                element_ty,
                element_size,
                big_endian,
            } = &cursor
            {
                let packet_offset = match member {
                    PathMember::Int { val, .. } => {
                        let index = usize::try_from(*val).map_err(|_| {
                            CompileError::UnsupportedInstruction(format!(
                                "typed field path '{}' requires a non-negative packet scalar index",
                                path_desc
                            ))
                        })?;
                        base_offset
                            .checked_add(index.checked_mul(*element_size).ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "typed field path '{}' packet scalar index overflowed",
                                    path_desc
                                ))
                            })?)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "typed field path '{}' offset overflowed",
                                    path_desc
                                ))
                            })?
                    }
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' expects a numeric index after packet scalar view",
                            path_desc
                        )));
                    }
                };

                if !is_last {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' does not support nested projection after a packet scalar index",
                        path_desc
                    )));
                }

                let packet_ptr_vreg = if packet_offset == 0 {
                    *base_vreg
                } else {
                    let ptr_vreg = self.func.alloc_vreg();
                    self.vreg_type_hints.insert(
                        ptr_vreg,
                        MirType::Ptr {
                            pointee: Box::new(element_ty.clone()),
                            address_space: AddressSpace::Packet,
                        },
                    );
                    self.emit(MirInst::BinOp {
                        dst: ptr_vreg,
                        op: BinOpKind::Add,
                        lhs: MirValue::VReg(*base_vreg),
                        rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                            packet_offset,
                            path_desc,
                        )?)),
                    });
                    ptr_vreg
                };
                let packet_ptr_vreg = self.packet_load_ptr_vreg(
                    packet_ptr_vreg,
                    MirType::Ptr {
                        pointee: Box::new(MirType::U8),
                        address_space: AddressSpace::Packet,
                    },
                    dst_vreg,
                );

                self.emit_xdp_packet_guarded_load(
                    dst_vreg,
                    packet_ptr_vreg,
                    element_ty,
                    path_desc,
                )?;
                if *big_endian {
                    self.emit_packet_big_endian_scalar_normalize(dst_vreg, element_ty)?;
                }
                return Ok(element_ty.clone());
            }

            loop {
                let ValueCursor::Pointer {
                    base_vreg,
                    address_space,
                    base_offset,
                    target_ty,
                    direct,
                } = &cursor
                else {
                    break;
                };
                let MirType::Ptr {
                    pointee,
                    address_space: next_space,
                } = target_ty
                else {
                    break;
                };
                if *direct && matches!(member, PathMember::Int { .. }) {
                    break;
                }

                let current_base_vreg = *base_vreg;
                let current_address_space = *address_space;
                let current_base_offset = *base_offset;
                let next_space = *next_space;
                let ptr_ty = MirType::Ptr {
                    pointee: pointee.clone(),
                    address_space: next_space,
                };
                let ptr_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(ptr_vreg, ptr_ty.clone());
                match current_address_space {
                    AddressSpace::Stack | AddressSpace::Map => {
                        self.emit(MirInst::Load {
                            dst: ptr_vreg,
                            ptr: current_base_vreg,
                            offset: Self::trampoline_projection_offset_i32(
                                current_base_offset,
                                path_desc,
                            )?,
                            ty: ptr_ty,
                        });
                    }
                    AddressSpace::Kernel | AddressSpace::User => {
                        let pointer_slot =
                            self.func
                                .alloc_stack_slot(align_to_eight(8), 8, StackSlotKind::Local);
                        self.record_stack_slot_type(pointer_slot, ptr_ty.clone());
                        self.emit_trampoline_probe_read_to_slot(
                            current_base_vreg,
                            current_address_space,
                            current_base_offset,
                            pointer_slot,
                            &ptr_ty,
                            path_desc,
                        )?;
                        self.emit(MirInst::LoadSlot {
                            dst: ptr_vreg,
                            slot: pointer_slot,
                            offset: 0,
                            ty: ptr_ty,
                        });
                    }
                    AddressSpace::Packet => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "xdp packet path '{}' does not support nested pointer dereferences",
                            path_desc
                        )));
                    }
                }
                cursor = ValueCursor::Pointer {
                    base_vreg: ptr_vreg,
                    address_space: next_space,
                    base_offset: 0,
                    target_ty: pointee.as_ref().clone(),
                    direct: true,
                };
            }

            let ValueCursor::Pointer {
                base_vreg,
                address_space,
                base_offset,
                target_ty,
                direct,
            } = &cursor
            else {
                continue;
            };

            if *address_space == AddressSpace::Packet {
                if let Some(kind) = Self::packet_payload_step_kind(target_ty, member) {
                    let payload_ptr_vreg = self.emit_packet_payload_ptr_step(
                        *base_vreg,
                        *base_offset,
                        kind,
                        path_desc,
                    )?;
                    if is_last {
                        self.vreg_type_hints.insert(
                            dst_vreg,
                            MirType::Ptr {
                                pointee: Box::new(MirType::U8),
                                address_space: AddressSpace::Packet,
                            },
                        );
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::VReg(payload_ptr_vreg),
                        });
                        return Ok(MirType::U8);
                    }

                    cursor = ValueCursor::Pointer {
                        base_vreg: payload_ptr_vreg,
                        address_space: *address_space,
                        base_offset: 0,
                        target_ty: MirType::U8,
                        direct: true,
                    };
                    continue;
                }

                if let Some(TypedProjectionStep {
                    offset: view_offset,
                    ty: view_ty,
                    ..
                }) = Self::packet_header_view_spec(target_ty, member)
                {
                    let field_offset = base_offset.checked_add(view_offset).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' offset overflowed",
                            path_desc
                        ))
                    })?;

                    if is_last {
                        self.vreg_type_hints.insert(
                            dst_vreg,
                            MirType::Ptr {
                                pointee: Box::new(view_ty.clone()),
                                address_space: AddressSpace::Packet,
                            },
                        );
                        if field_offset == 0 {
                            self.emit(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::VReg(*base_vreg),
                            });
                        } else {
                            self.emit(MirInst::BinOp {
                                dst: dst_vreg,
                                op: BinOpKind::Add,
                                lhs: MirValue::VReg(*base_vreg),
                                rhs: MirValue::Const(i64::from(
                                    Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                )),
                            });
                        }
                        return Ok(view_ty);
                    }

                    cursor = ValueCursor::Pointer {
                        base_vreg: *base_vreg,
                        address_space: *address_space,
                        base_offset: field_offset,
                        target_ty: view_ty,
                        direct: false,
                    };
                    continue;
                }

                if matches!(target_ty, MirType::U8)
                    && let Some((element_ty, element_size, big_endian)) =
                        Self::packet_scalar_view_spec(member)
                {
                    if is_last {
                        let packet_ptr_vreg = self.packet_load_ptr_vreg(
                            *base_vreg,
                            MirType::Ptr {
                                pointee: Box::new(target_ty.clone()),
                                address_space: AddressSpace::Packet,
                            },
                            dst_vreg,
                        );
                        self.emit_xdp_packet_guarded_load(
                            dst_vreg,
                            packet_ptr_vreg,
                            &element_ty,
                            path_desc,
                        )?;
                        if big_endian {
                            self.emit_packet_big_endian_scalar_normalize(dst_vreg, &element_ty)?;
                        }
                        return Ok(element_ty);
                    }

                    cursor = ValueCursor::PacketScalar {
                        base_vreg: *base_vreg,
                        base_offset: *base_offset,
                        element_ty,
                        element_size,
                        big_endian,
                    };
                    continue;
                }
            }

            let TypedProjectionStep {
                offset: segment_offset,
                ty: next_ty,
                bitfield,
                packet_big_endian,
            } = match (direct, member) {
                (true, PathMember::Int { val, .. })
                    if !matches!(target_ty, MirType::Array { .. }) =>
                {
                    Self::resolve_pointer_sequence_index_step(target_ty, *val, path_desc)?
                }
                _ => Self::resolve_typed_value_projection_step(target_ty, member, path_desc)?,
            };
            let field_offset = base_offset.checked_add(segment_offset).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' offset overflowed",
                    path_desc
                ))
            })?;

            if is_last {
                if projected_by_ref(&next_ty) {
                    match address_space {
                        AddressSpace::Stack | AddressSpace::Map => {
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: *address_space,
                                },
                            );
                            if field_offset == 0 {
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::VReg(*base_vreg),
                                });
                            } else {
                                self.emit(MirInst::BinOp {
                                    dst: dst_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                            }
                        }
                        AddressSpace::Kernel | AddressSpace::User => {
                            let projected_slot = self.func.alloc_stack_slot(
                                align_to_eight(next_ty.size()),
                                8,
                                StackSlotKind::Local,
                            );
                            self.record_stack_slot_type(projected_slot, next_ty.clone());
                            self.emit_trampoline_probe_read_to_slot(
                                *base_vreg,
                                *address_space,
                                field_offset,
                                projected_slot,
                                &next_ty,
                                path_desc,
                            )?;
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: AddressSpace::Stack,
                                },
                            );
                            self.emit(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::StackSlot(projected_slot),
                            });
                        }
                        AddressSpace::Packet => {
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: *address_space,
                                },
                            );
                            if field_offset == 0 {
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::VReg(*base_vreg),
                                });
                            } else {
                                self.emit(MirInst::BinOp {
                                    dst: dst_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                            }
                        }
                    }
                } else {
                    match address_space {
                        AddressSpace::Stack | AddressSpace::Map => {
                            let loaded_vreg = if bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(storage_vreg, next_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: storage_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: next_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    &next_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, next_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: dst_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: next_ty.clone(),
                                });
                            }
                        }
                        AddressSpace::Kernel | AddressSpace::User => {
                            let projected_slot = self.func.alloc_stack_slot(
                                align_to_eight(next_ty.size()),
                                8,
                                StackSlotKind::Local,
                            );
                            self.record_stack_slot_type(projected_slot, next_ty.clone());
                            self.emit_trampoline_probe_read_to_slot(
                                *base_vreg,
                                *address_space,
                                field_offset,
                                projected_slot,
                                &next_ty,
                                path_desc,
                            )?;
                            let loaded_vreg = if bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(storage_vreg, next_ty.clone());
                                self.emit(MirInst::LoadSlot {
                                    dst: storage_vreg,
                                    slot: projected_slot,
                                    offset: 0,
                                    ty: next_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    &next_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, next_ty.clone());
                                self.emit(MirInst::LoadSlot {
                                    dst: dst_vreg,
                                    slot: projected_slot,
                                    offset: 0,
                                    ty: next_ty.clone(),
                                });
                            }
                        }
                        AddressSpace::Packet => {
                            if bitfield.is_some() {
                                return Err(CompileError::UnsupportedInstruction(format!(
                                    "xdp packet path '{}' does not support bitfield extraction",
                                    path_desc
                                )));
                            }

                            let packet_ptr_vreg = if field_offset == 0 {
                                *base_vreg
                            } else {
                                let ptr_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(
                                    ptr_vreg,
                                    MirType::Ptr {
                                        pointee: Box::new(next_ty.clone()),
                                        address_space: AddressSpace::Packet,
                                    },
                                );
                                self.emit(MirInst::BinOp {
                                    dst: ptr_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                                ptr_vreg
                            };
                            let packet_ptr_vreg = self.packet_load_ptr_vreg(
                                packet_ptr_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: AddressSpace::Packet,
                                },
                                dst_vreg,
                            );
                            self.emit_xdp_packet_guarded_load(
                                dst_vreg,
                                packet_ptr_vreg,
                                &next_ty,
                                path_desc,
                            )?;
                            if packet_big_endian {
                                self.emit_packet_big_endian_scalar_normalize(dst_vreg, &next_ty)?;
                            }
                        }
                    }
                }
                return Ok(next_ty);
            }

            cursor = ValueCursor::Pointer {
                base_vreg: *base_vreg,
                address_space: *address_space,
                base_offset: field_offset,
                target_ty: next_ty,
                direct: false,
            };
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "empty typed field path '{}'",
            path_desc
        )))
    }

    pub(super) fn lower_dynamic_typed_numeric_get(
        &mut self,
        dst_reg: RegId,
        base_vreg: VReg,
        base_runtime_ty: &MirType,
        idx: MirValue,
    ) -> Result<MirType, CompileError> {
        let dst_vreg = self.get_vreg(dst_reg);
        let path_desc = match &idx {
            MirValue::Const(value) => format!("get {}", value),
            _ => "get <dynamic-index>".to_string(),
        };

        let MirType::Ptr {
            pointee,
            address_space,
        } = base_runtime_ty
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "numeric get requires a typed pointer value, got {:?}",
                base_runtime_ty
            )));
        };

        let (element_ty, element_size) = match pointee.as_ref() {
            MirType::Array { elem, .. } => (elem.as_ref().clone(), elem.size()),
            other => (other.clone(), other.size()),
        };

        let base_copy = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: base_copy,
            src: MirValue::VReg(base_vreg),
        });
        self.vreg_type_hints
            .insert(base_copy, base_runtime_ty.clone());

        let scaled_idx = if element_size == 1 {
            idx.clone()
        } else {
            match idx {
                MirValue::Const(value) => {
                    let scaled = value
                        .checked_mul(i64::try_from(element_size).map_err(|_| {
                            CompileError::UnsupportedInstruction(format!(
                                "numeric get element size {} is too large",
                                element_size
                            ))
                        })?)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "numeric get index overflowed".into(),
                            )
                        })?;
                    MirValue::Const(scaled)
                }
                MirValue::VReg(idx_vreg) => {
                    let scaled_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: scaled_vreg,
                        op: BinOpKind::Mul,
                        lhs: MirValue::VReg(idx_vreg),
                        rhs: MirValue::Const(i64::try_from(element_size).map_err(|_| {
                            CompileError::UnsupportedInstruction(format!(
                                "numeric get element size {} is too large",
                                element_size
                            ))
                        })?),
                    });
                    MirValue::VReg(scaled_vreg)
                }
                MirValue::StackSlot(_) => {
                    return Err(CompileError::UnsupportedInstruction(
                        "numeric get does not support stack-slot indices".into(),
                    ));
                }
            }
        };

        let element_ptr_vreg = self.func.alloc_vreg();
        let element_ptr_ty = MirType::Ptr {
            pointee: Box::new(element_ty.clone()),
            address_space: *address_space,
        };
        self.vreg_type_hints
            .insert(element_ptr_vreg, element_ptr_ty.clone());
        self.emit(MirInst::BinOp {
            dst: element_ptr_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(base_copy),
            rhs: scaled_idx,
        });

        match address_space {
            AddressSpace::Kernel | AddressSpace::User => {
                if matches!(element_ty, MirType::Array { .. } | MirType::Struct { .. }) {
                    let projected_slot = self.func.alloc_stack_slot(
                        align_to_eight(element_ty.size()),
                        8,
                        StackSlotKind::Local,
                    );
                    self.record_stack_slot_type(projected_slot, element_ty.clone());
                    self.emit_trampoline_probe_read_to_slot(
                        element_ptr_vreg,
                        *address_space,
                        0,
                        projected_slot,
                        &element_ty,
                        &path_desc,
                    )?;
                    self.vreg_type_hints.insert(
                        dst_vreg,
                        MirType::Ptr {
                            pointee: Box::new(element_ty.clone()),
                            address_space: AddressSpace::Stack,
                        },
                    );
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::StackSlot(projected_slot),
                    });
                } else {
                    let projected_slot = self.func.alloc_stack_slot(
                        align_to_eight(element_ty.size()),
                        8,
                        StackSlotKind::Local,
                    );
                    self.record_stack_slot_type(projected_slot, element_ty.clone());
                    self.emit_trampoline_probe_read_to_slot(
                        element_ptr_vreg,
                        *address_space,
                        0,
                        projected_slot,
                        &element_ty,
                        &path_desc,
                    )?;
                    self.vreg_type_hints.insert(dst_vreg, element_ty.clone());
                    self.emit(MirInst::LoadSlot {
                        dst: dst_vreg,
                        slot: projected_slot,
                        offset: 0,
                        ty: element_ty.clone(),
                    });
                }
            }
            AddressSpace::Packet => {
                if matches!(element_ty, MirType::Array { .. } | MirType::Struct { .. }) {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "numeric get on xdp packet data currently supports only scalar elements, got {:?}",
                        element_ty
                    )));
                }
                self.emit_xdp_packet_guarded_load(
                    dst_vreg,
                    element_ptr_vreg,
                    &element_ty,
                    &path_desc,
                )?;
            }
            AddressSpace::Stack | AddressSpace::Map => {
                if matches!(element_ty, MirType::Array { .. } | MirType::Struct { .. }) {
                    self.vreg_type_hints.insert(
                        dst_vreg,
                        MirType::Ptr {
                            pointee: Box::new(element_ty.clone()),
                            address_space: *address_space,
                        },
                    );
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(element_ptr_vreg),
                    });
                } else {
                    self.vreg_type_hints.insert(dst_vreg, element_ty.clone());
                    self.emit(MirInst::Load {
                        dst: dst_vreg,
                        ptr: element_ptr_vreg,
                        offset: 0,
                        ty: element_ty.clone(),
                    });
                }
            }
        }

        let meta = self.get_or_create_metadata(dst_reg);
        meta.is_context = false;
        meta.field_type = Some(element_ty.clone());

        Ok(element_ty)
    }

    /// Lower FollowCellPath instruction (context field access like $ctx.pid)
    pub(super) fn lower_follow_cell_path(
        &mut self,
        src_dst: RegId,
        path_reg: RegId,
    ) -> Result<(), CompileError> {
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

        let dst_vreg = self.get_vreg(src_dst);

        if !self.is_context_reg(src_dst) {
            let path_desc = Self::typed_value_path_desc(&path.members);
            let base_runtime_ty = self
                .typed_value_runtime_type(src_dst, dst_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' requires type information for the base value",
                        path_desc
                    ))
                })?;
            let base_vreg = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: base_vreg,
                src: MirValue::VReg(dst_vreg),
            });
            self.vreg_type_hints.insert(
                base_vreg,
                self.vreg_type_hints
                    .get(&dst_vreg)
                    .cloned()
                    .unwrap_or_else(|| base_runtime_ty.clone()),
            );
            let projected_ty = self.lower_typed_value_projection(
                dst_vreg,
                base_vreg,
                &base_runtime_ty,
                &path.members,
                &path_desc,
            )?;
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;
            meta.field_type = Some(projected_ty);
            return Ok(());
        }

        let field_name = Self::ctx_path_member_name(&path.members[0])?;
        let ctx_field = Self::ctx_field_from_name(field_name)?;
        if let Some(ctx) = self.probe_ctx {
            ctx.validate_ctx_field_access(&ctx_field)?;
        }
        let trampoline_value_spec = self.trampoline_value_spec(&ctx_field)?;

        if path.members.len() > 1 {
            if matches!(ctx_field, CtxField::Data | CtxField::DataEnd) {
                let base_ty = MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Packet,
                };
                let base_vreg = self.func.alloc_vreg();
                self.emit(MirInst::LoadCtxField {
                    dst: base_vreg,
                    field: ctx_field.clone(),
                    slot: None,
                });
                self.vreg_type_hints.insert(base_vreg, base_ty.clone());
                let projected_ty = self.lower_typed_value_projection(
                    dst_vreg,
                    base_vreg,
                    &base_ty,
                    &path.members[1..],
                    &Self::typed_value_path_desc(&path.members),
                )?;
                let meta = self.get_or_create_metadata(src_dst);
                meta.is_context = false;
                meta.field_type = Some(projected_ty);
                return Ok(());
            }

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
            let root_runtime_ty = self
                .trampoline_root_type_info(&ctx_field)?
                .and_then(|type_info| Self::root_trampoline_value_types(&type_info, spec.kind))
                .map(|(_, runtime_ty)| runtime_ty)
                .unwrap_or_else(|| match spec.kind {
                    TrampolineValueKind::Aggregate { size_bytes } => MirType::Ptr {
                        pointee: Box::new(MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: size_bytes,
                        }),
                        address_space: AddressSpace::Stack,
                    },
                    TrampolineValueKind::Pointer { user_space } => {
                        Self::trampoline_pointer_type(if user_space {
                            AddressSpace::User
                        } else {
                            AddressSpace::Kernel
                        })
                    }
                    TrampolineValueKind::Scalar => MirType::I64,
                });
            self.lower_trampoline_field_projection(
                dst_vreg,
                &ctx_field,
                spec,
                &projection,
                &root_runtime_ty,
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
        let precise_trampoline_types = trampoline_value_spec
            .zip(self.trampoline_root_type_info(&ctx_field)?)
            .and_then(|(spec, type_info)| Self::root_trampoline_value_types(&type_info, spec.kind));
        if let (
            Some(slot),
            Some((
                _,
                MirType::Ptr {
                    pointee,
                    address_space,
                },
            )),
        ) = (slot, precise_trampoline_types.as_ref())
            && *address_space == AddressSpace::Stack
        {
            self.record_stack_slot_type(slot, pointee.as_ref().clone());
        }
        self.emit(MirInst::LoadCtxField {
            dst: dst_vreg,
            field: ctx_field.clone(),
            slot,
        });

        let (field_type, runtime_type_hint) = match &ctx_field {
            CtxField::Comm => {
                let semantic_ty = MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 16,
                };
                let runtime_ty = MirType::Ptr {
                    pointee: Box::new(semantic_ty.clone()),
                    address_space: AddressSpace::Stack,
                };
                (semantic_ty, Some(runtime_ty))
            }
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid => {
                (MirType::I32, Some(MirType::I32))
            }
            CtxField::Cpu
            | CtxField::PacketLen
            | CtxField::IngressIfindex
            | CtxField::RxQueueIndex
            | CtxField::EgressIfindex => (MirType::U32, Some(MirType::U32)),
            CtxField::Data | CtxField::DataEnd => {
                let ptr_ty = MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Packet,
                };
                (ptr_ty.clone(), Some(ptr_ty))
            }
            CtxField::Timestamp => (MirType::U64, Some(MirType::U64)),
            _ => precise_trampoline_types
                .map(|(semantic_ty, runtime_ty)| (semantic_ty, Some(runtime_ty)))
                .unwrap_or_else(|| match trampoline_value_spec.map(|spec| spec.kind) {
                    Some(TrampolineValueKind::Aggregate { size_bytes }) => (
                        MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: size_bytes,
                        },
                        None,
                    ),
                    _ => (MirType::I64, None),
                }),
        };
        if let Some(runtime_ty) = runtime_type_hint {
            self.vreg_type_hints.insert(dst_vreg, runtime_ty);
        }

        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = false;
        meta.field_type = Some(field_type);

        Ok(())
    }
}
