use super::*;
use crate::compiler::ProgramIntrinsic;
use crate::compiler::instruction::{
    BpfHelper, kfunc_pointer_arg_fixed_size, kfunc_pointer_arg_requires_stack_slot_base,
};
use crate::compiler::mir::AddressSpace;

#[derive(Debug, Clone)]
pub(super) struct ScalarKfuncOutArgWriteback {
    slot: StackSlotId,
    source_var: VarId,
    scalar_ty: MirType,
    original_arg_vreg: VReg,
}

impl<'a> HirToMirLowering<'a> {
    pub(super) fn aggregate_call_value_type<'b>(ty: &'b MirType) -> Option<&'b MirType> {
        match ty {
            MirType::Array { .. } | MirType::Struct { .. } => Some(ty),
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } if matches!(
                pointee.as_ref(),
                MirType::Array { .. } | MirType::Struct { .. }
            ) =>
            {
                Some(pointee.as_ref())
            }
            _ => None,
        }
    }

    pub(super) fn aggregate_call_value_byte_array_len(ty: &MirType) -> Option<usize> {
        match ty {
            ty if ty.byte_array_len().is_some() => ty.byte_array_len(),
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } => pointee.byte_array_len(),
            _ => None,
        }
    }

    pub(super) fn literal_string_arg(
        &self,
        reg: RegId,
        context: &str,
    ) -> Result<String, CompileError> {
        self.get_metadata(reg)
            .and_then(|m| m.literal_string.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} requires a compile-time string literal"
                ))
            })
    }

    pub(super) fn lower_probe_read_string(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        ptr_vreg: VReg,
        user_space: bool,
        aligned_len: usize,
    ) -> Result<(), CompileError> {
        let slot = self
            .func
            .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
        let string_ty = MirType::Array {
            elem: Box::new(MirType::U8),
            len: aligned_len,
        };
        self.record_stack_slot_type(slot, string_ty.clone());

        let slot_ptr_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: slot_ptr_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            slot_ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(string_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        self.vreg_type_hints.insert(
            ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: if user_space {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                },
            },
        );

        let raw_len_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: raw_len_vreg,
            helper: if user_space {
                BpfHelper::ProbeReadUserStr as u32
            } else {
                BpfHelper::ProbeReadKernelStr as u32
            },
            args: vec![
                MirValue::VReg(slot_ptr_vreg),
                MirValue::Const(aligned_len as i64),
                MirValue::VReg(ptr_vreg),
            ],
        });
        self.vreg_type_hints.insert(raw_len_vreg, MirType::I64);

        let has_content_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: has_content_vreg,
            op: BinOpKind::Gt,
            lhs: MirValue::VReg(raw_len_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(has_content_vreg, MirType::Bool);

        let len_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(len_vreg, MirType::U64);
        let len_ok_block = self.func.alloc_block();
        let len_zero_block = self.func.alloc_block();
        let continue_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: has_content_vreg,
            if_true: len_ok_block,
            if_false: len_zero_block,
        });

        self.current_block = len_ok_block;
        self.emit(MirInst::BinOp {
            dst: len_vreg,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(raw_len_vreg),
            rhs: MirValue::Const(1),
        });
        self.terminate(MirInst::Jump {
            target: continue_block,
        });

        self.current_block = len_zero_block;
        self.emit(MirInst::Copy {
            dst: len_vreg,
            src: MirValue::Const(0),
        });
        self.terminate(MirInst::Jump {
            target: continue_block,
        });

        self.current_block = continue_block;
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            dst_vreg,
            MirType::Ptr {
                pointee: Box::new(string_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );

        let meta = self.get_or_create_metadata(src_dst);
        meta.string_slot = Some(slot);
        meta.string_len_vreg = Some(len_vreg);
        meta.string_len_bound = Some(aligned_len.saturating_sub(1));
        meta.field_type = Some(string_ty);
        Ok(())
    }

    pub(super) fn parse_generic_map_kind(kind: &str) -> Option<MapKind> {
        match kind {
            "hash" => Some(MapKind::Hash),
            "array" => Some(MapKind::Array),
            "queue" => Some(MapKind::Queue),
            "stack" => Some(MapKind::Stack),
            "lpm-trie" | "lpm_trie" | "lpmtrie" => Some(MapKind::LpmTrie),
            "lru-hash" | "lru_hash" | "lruhash" => Some(MapKind::LruHash),
            "per-cpu-hash" | "percpu-hash" | "per_cpu_hash" => Some(MapKind::PerCpuHash),
            "per-cpu-array" | "percpu-array" | "per_cpu_array" => Some(MapKind::PerCpuArray),
            "lru-per-cpu-hash" | "lru-percpu-hash" | "lru_per_cpu_hash" | "lrupercpuhash" => {
                Some(MapKind::LruPerCpuHash)
            }
            "sock-map" | "sock_map" | "sockmap" => Some(MapKind::SockMap),
            "sock-hash" | "sock_hash" | "sockhash" => Some(MapKind::SockHash),
            _ => None,
        }
    }

    pub(super) fn generic_map_kind_arg(&self, context: &str) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Ok(MapKind::Hash);
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        Self::parse_generic_map_kind(&kind).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{context} --kind must be one of: hash, array, queue, stack, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, lru-per-cpu-hash, sockmap, sockhash"
            ))
        })
    }

    pub(super) fn required_queue_stack_map_kind_arg(
        &self,
        context: &str,
    ) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind queue or --kind stack"
            )));
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        match Self::parse_generic_map_kind(&kind) {
            Some(MapKind::Queue) => Ok(MapKind::Queue),
            Some(MapKind::Stack) => Ok(MapKind::Stack),
            Some(other) => Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind queue or --kind stack, got {:?}",
                other
            ))),
            None => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind must be one of: queue, stack"
            ))),
        }
    }

    pub(super) fn validate_generic_map_name(
        &self,
        map_name: &str,
        context: &str,
    ) -> Result<(), CompileError> {
        let mut chars = map_name.chars();
        let Some(first) = chars.next() else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} map name must not be empty"
            )));
        };
        if !(first == '_' || first.is_ascii_alphabetic())
            || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} map name '{map_name}' must match [A-Za-z_][A-Za-z0-9_]*"
            )));
        }
        Ok(())
    }

    pub(super) fn validate_generic_map_delete_kind(
        &self,
        map_kind: MapKind,
        map_name: &str,
    ) -> Result<(), CompileError> {
        if matches!(map_kind, MapKind::Array | MapKind::PerCpuArray) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map delete is not supported for array map kind {:?} ('{}')",
                map_kind, map_name
            )));
        }
        if matches!(map_kind, MapKind::Queue | MapKind::Stack) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map delete is not supported for map kind {:?} ('{}')",
                map_kind, map_name
            )));
        }
        if matches!(map_kind, MapKind::SockMap | MapKind::SockHash) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-delete is not supported for socket map kind {:?} ('{}'); socket maps require specialized redirect/update helpers instead of generic map-delete",
                map_kind, map_name
            )));
        }
        Ok(())
    }

    pub(super) fn validate_generic_map_lookup_kind(
        &self,
        map_kind: MapKind,
        map_name: &str,
    ) -> Result<(), CompileError> {
        if matches!(map_kind, MapKind::Queue | MapKind::Stack) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-get is not supported for map kind {:?} ('{}'); use map-push and future queue/stack-specific operations instead",
                map_kind, map_name
            )));
        }
        if matches!(map_kind, MapKind::SockMap | MapKind::SockHash) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-get is not supported for socket map kind {:?} ('{}'); use specialized socket-map helpers instead",
                map_kind, map_name
            )));
        }
        Ok(())
    }

    pub(super) fn validate_generic_map_update_kind(
        &self,
        map_kind: MapKind,
        map_name: &str,
    ) -> Result<(), CompileError> {
        if matches!(map_kind, MapKind::Queue | MapKind::Stack) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-put is not supported for map kind {:?} ('{}'); use map-push instead",
                map_kind, map_name
            )));
        }
        if matches!(map_kind, MapKind::SockMap | MapKind::SockHash) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-put is not supported for socket map kind {:?} ('{}'); use specialized socket-map update helpers instead",
                map_kind, map_name
            )));
        }
        Ok(())
    }

    pub(super) fn require_only_named_args(
        &self,
        context: &str,
        allowed: &[&str],
    ) -> Result<(), CompileError> {
        for key in self.named_args.keys() {
            if !allowed.iter().any(|allowed_key| allowed_key == key) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} does not accept named argument '{}'",
                    key
                )));
            }
        }
        Ok(())
    }

    pub(super) fn reset_call_result_metadata(&mut self, reg: RegId) {
        *self.get_or_create_metadata(reg) = RegMetadata::default();
    }

    pub(super) fn materialize_scalar_kfunc_out_arg(
        &mut self,
        kfunc: &str,
        arg_idx: usize,
        arg_vreg: VReg,
        arg_reg: Option<RegId>,
    ) -> Result<(VReg, Option<ScalarKfuncOutArgWriteback>), CompileError> {
        let Some(arg_reg) = arg_reg else {
            return Ok((arg_vreg, None));
        };
        if matches!(
            self.vreg_type_hints.get(&arg_vreg),
            Some(MirType::Ptr { .. })
        ) {
            return Ok((arg_vreg, None));
        }

        if !kfunc_pointer_arg_requires_stack_slot_base(kfunc, arg_idx) {
            return Ok((arg_vreg, None));
        }

        let Some(source_var) = self.get_metadata(arg_reg).and_then(|meta| meta.source_var) else {
            return Ok((arg_vreg, None));
        };
        let Some(fixed_size) = kfunc_pointer_arg_fixed_size(kfunc, arg_idx) else {
            return Ok((arg_vreg, None));
        };
        let Some(scalar_ty) = self.direct_scalar_var_out_arg_type(arg_reg, arg_vreg, fixed_size)
        else {
            return Ok((arg_vreg, None));
        };

        let slot = self.func.alloc_stack_slot(
            align_to_eight(fixed_size.max(scalar_ty.size())),
            8,
            StackSlotKind::Local,
        );
        self.record_stack_slot_type(slot, scalar_ty.clone());
        self.emit(MirInst::StoreSlot {
            slot,
            offset: 0,
            val: MirValue::VReg(arg_vreg),
            ty: scalar_ty.clone(),
        });

        let ptr_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: ptr_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(scalar_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );

        Ok((
            ptr_vreg,
            Some(ScalarKfuncOutArgWriteback {
                slot,
                source_var,
                scalar_ty,
                original_arg_vreg: arg_vreg,
            }),
        ))
    }

    pub(super) fn write_back_scalar_kfunc_out_args(
        &mut self,
        writebacks: Vec<ScalarKfuncOutArgWriteback>,
    ) -> Result<(), CompileError> {
        for writeback in writebacks {
            let reloaded_vreg = self.func.alloc_vreg();
            self.emit(MirInst::LoadSlot {
                dst: reloaded_vreg,
                slot: writeback.slot,
                offset: 0,
                ty: writeback.scalar_ty.clone(),
            });
            self.vreg_type_hints
                .insert(reloaded_vreg, writeback.scalar_ty.clone());
            self.emit(MirInst::Copy {
                dst: writeback.original_arg_vreg,
                src: MirValue::VReg(reloaded_vreg),
            });
            self.vreg_type_hints
                .insert(writeback.original_arg_vreg, writeback.scalar_ty.clone());
            self.write_back_direct_scalar_var(
                writeback.source_var,
                writeback.scalar_ty,
                reloaded_vreg,
            )?;
        }
        Ok(())
    }

    pub(super) fn validate_intrinsic_support(
        &self,
        intrinsic: ProgramIntrinsic,
    ) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Ok(());
        };
        if ctx.probe_type.supports_intrinsic(intrinsic) {
            return Ok(());
        }
        Err(CompileError::UnsupportedInstruction(format!(
            "{} is not supported on {} programs",
            intrinsic.command_name(),
            ctx.probe_type.canonical_prefix()
        )))
    }

    pub(super) fn set_call_args(&mut self, args: &HirCallArgs) -> Result<(), CompileError> {
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();

        for reg in &args.positional {
            let vreg = self.get_vreg(*reg);
            self.positional_args.push((vreg, *reg));
        }
        for reg in &args.rest {
            let vreg = self.get_vreg(*reg);
            self.positional_args.push((vreg, *reg));
        }
        for (name, reg) in &args.named {
            let name = std::str::from_utf8(name)
                .map_err(|_| CompileError::UnsupportedInstruction("Invalid arg name".into()))?
                .to_string();
            let vreg = self.get_vreg(*reg);
            self.named_args.insert(name, (vreg, *reg));
        }
        for flag in &args.flags {
            let flag = std::str::from_utf8(flag)
                .map_err(|_| CompileError::UnsupportedInstruction("Invalid flag name".into()))?
                .to_string();
            self.named_flags.push(flag);
        }

        Ok(())
    }

    pub(super) fn clear_call_state(&mut self) {
        self.pipeline_input = None;
        self.pipeline_input_reg = None;
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();
    }

    pub(super) fn const_vreg(&mut self, value: i64) -> VReg {
        let vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: vreg,
            src: MirValue::Const(value),
        });
        vreg
    }

    pub(super) fn input_vreg_for_call(&mut self, src_dst: RegId) -> VReg {
        if let Some(vreg) = self.pipeline_input {
            return vreg;
        }
        if self.reg_map.contains_key(&src_dst.get()) {
            return self.get_vreg(src_dst);
        }
        self.const_vreg(0)
    }
}
