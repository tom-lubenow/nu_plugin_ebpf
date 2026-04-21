use super::*;
use crate::compiler::ctx_field_schema::{synthetic_bpf_sock_type, synthetic_bpf_tcp_sock_type};
use crate::compiler::instruction::BpfHelper;
use crate::kernel_btf::KernelBtf;

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn try_lower_helper_backed_typed_projection(
        &mut self,
        dst_reg: RegId,
        dst_vreg: VReg,
        base_vreg: VReg,
        base_runtime_ty: &MirType,
        path_members: &[PathMember],
        path_desc: &str,
        root_ctx_field: Option<&CtxField>,
        projected_semantics: Option<&AnnotatedValueSemantics>,
    ) -> Result<Option<MirType>, CompileError> {
        if let Some(projected_ty) = self.try_lower_socket_cgroup_projection(
            dst_vreg,
            base_vreg,
            path_members,
            path_desc,
            root_ctx_field,
        )? {
            return Ok(Some(projected_ty));
        }

        if let Some(projected_ty) = self.try_lower_socket_helper_projection(
            dst_reg,
            dst_vreg,
            base_vreg,
            path_members,
            path_desc,
            root_ctx_field,
            projected_semantics,
        )? {
            return Ok(Some(projected_ty));
        }

        self.try_lower_task_pt_regs_projection(
            dst_vreg,
            base_vreg,
            base_runtime_ty,
            path_members,
            path_desc,
            root_ctx_field,
        )
    }

    fn try_lower_socket_cgroup_projection(
        &mut self,
        dst_vreg: VReg,
        base_vreg: VReg,
        path_members: &[PathMember],
        path_desc: &str,
        root_ctx_field: Option<&CtxField>,
    ) -> Result<Option<MirType>, CompileError> {
        let socket_cgroup_projection = if root_ctx_field == Some(&CtxField::Socket) {
            match path_members {
                [PathMember::String { val, .. }] if val == "cgroup_id" => {
                    Some((BpfHelper::SkCgroupId, Vec::new()))
                }
                [
                    PathMember::String { val, .. },
                    PathMember::Int { val: level, .. },
                ] if val == "ancestor_cgroup_id" => {
                    let level_i32 = i32::try_from(*level).map_err(|_| {
                        CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' requires ancestor level 0..{}, got {}",
                            path_desc,
                            i32::MAX,
                            level
                        ))
                    })?;
                    Some((
                        BpfHelper::SkAncestorCgroupId,
                        vec![MirValue::Const(i64::from(level_i32))],
                    ))
                }
                [PathMember::String { val, .. }, ..] if val == "ancestor_cgroup_id" => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' requires a constant numeric ancestor level, e.g. ctx.sk.ancestor_cgroup_id.0",
                        path_desc
                    )));
                }
                _ => None,
            }
        } else {
            None
        };

        let Some((helper, mut helper_args)) = socket_cgroup_projection else {
            return Ok(None);
        };

        if let Some(message) = self.probe_ctx.and_then(|ctx| ctx.helper_call_error(helper)) {
            return Err(CompileError::UnsupportedInstruction(message));
        }
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });
        let has_socket_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: has_socket_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(base_vreg),
            rhs: MirValue::Const(0),
        });
        let helper_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: has_socket_vreg,
            if_true: helper_block,
            if_false: join_block,
        });

        self.current_block = helper_block;
        let mut args = vec![MirValue::VReg(base_vreg)];
        args.append(&mut helper_args);
        self.emit(MirInst::CallHelper {
            dst: dst_vreg,
            helper: helper as u32,
            args,
        });
        self.terminate(MirInst::Jump { target: join_block });

        self.current_block = join_block;
        self.vreg_type_hints.insert(dst_vreg, MirType::I64);
        Ok(Some(MirType::I64))
    }

    fn try_lower_socket_helper_projection(
        &mut self,
        dst_reg: RegId,
        dst_vreg: VReg,
        base_vreg: VReg,
        path_members: &[PathMember],
        path_desc: &str,
        root_ctx_field: Option<&CtxField>,
        projected_semantics: Option<&AnnotatedValueSemantics>,
    ) -> Result<Option<MirType>, CompileError> {
        let socket_helper_projection = if root_ctx_field == Some(&CtxField::Socket) {
            match path_members {
                [PathMember::String { val, .. }, rest @ ..]
                    if val == "tcp" || val == "tcp_sock" =>
                {
                    Some((
                        "ctx.sk.tcp",
                        BpfHelper::TcpSock,
                        MirType::Ptr {
                            pointee: Box::new(synthetic_bpf_tcp_sock_type()),
                            address_space: AddressSpace::Kernel,
                        },
                        rest,
                    ))
                }
                [PathMember::String { val, .. }, rest @ ..]
                    if val == "full" || val == "fullsock" || val == "full_sock" =>
                {
                    Some((
                        "ctx.sk.full",
                        BpfHelper::SkFullsock,
                        MirType::Ptr {
                            pointee: Box::new(synthetic_bpf_sock_type()),
                            address_space: AddressSpace::Kernel,
                        },
                        rest,
                    ))
                }
                [PathMember::String { val, .. }, rest @ ..] if val == "listener" => Some((
                    "ctx.sk.listener",
                    BpfHelper::GetListenerSock,
                    MirType::Ptr {
                        pointee: Box::new(synthetic_bpf_sock_type()),
                        address_space: AddressSpace::Kernel,
                    },
                    rest,
                )),
                _ => None,
            }
        } else {
            None
        };

        let Some((projection_name, helper, helper_ret_ty, field_members)) =
            socket_helper_projection
        else {
            return Ok(None);
        };

        if field_members.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "typed field path '{}' requires a socket field after {}, e.g. {}.family",
                path_desc, projection_name, projection_name
            )));
        }
        if let Some(message) = self.probe_ctx.and_then(|ctx| ctx.helper_call_error(helper)) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });
        let has_socket_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: has_socket_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(base_vreg),
            rhs: MirValue::Const(0),
        });
        let helper_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: has_socket_vreg,
            if_true: helper_block,
            if_false: join_block,
        });

        self.current_block = helper_block;
        let helper_ret_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(helper_ret_vreg, helper_ret_ty.clone());
        self.emit(MirInst::CallHelper {
            dst: helper_ret_vreg,
            helper: helper as u32,
            args: vec![MirValue::VReg(base_vreg)],
        });

        let has_helper_ret_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: has_helper_ret_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(helper_ret_vreg),
            rhs: MirValue::Const(0),
        });
        let field_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: has_helper_ret_vreg,
            if_true: field_block,
            if_false: join_block,
        });

        self.current_block = field_block;
        let projected_ty = self.lower_typed_value_projection(
            dst_reg,
            dst_vreg,
            helper_ret_vreg,
            &helper_ret_ty,
            field_members,
            path_desc,
            None,
            projected_semantics,
        )?;
        self.terminate(MirInst::Jump { target: join_block });

        self.current_block = join_block;
        Ok(Some(projected_ty))
    }

    fn try_lower_task_pt_regs_projection(
        &mut self,
        dst_vreg: VReg,
        base_vreg: VReg,
        base_runtime_ty: &MirType,
        path_members: &[PathMember],
        path_desc: &str,
        root_ctx_field: Option<&CtxField>,
    ) -> Result<Option<MirType>, CompileError> {
        let task_pt_regs_projection = if root_ctx_field == Some(&CtxField::Task)
            || base_runtime_ty.is_task_struct_ptr()
        {
            match path_members {
                [
                    PathMember::String { val, .. },
                    PathMember::String { val: reg, .. },
                ] if val == "pt_regs" => Some(reg.as_str()),
                [PathMember::String { val, .. }, ..] if val == "pt_regs" => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' requires a pt_regs register after ctx.task.pt_regs, e.g. ctx.task.pt_regs.arg0 or ctx.task.pt_regs.retval",
                        path_desc
                    )));
                }
                _ => None,
            }
        } else {
            None
        };

        let Some(register_name) = task_pt_regs_projection else {
            return Ok(None);
        };

        if let Some(message) = self
            .probe_ctx
            .and_then(|ctx| ctx.helper_call_error(BpfHelper::TaskPtRegs))
        {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        let offsets = KernelBtf::get().pt_regs_offsets().map_err(|err| {
            CompileError::UnsupportedInstruction(format!(
                "pt_regs register access unavailable: {err}"
            ))
        })?;
        let register_offset = match register_name {
            "arg0" => offsets.arg_offsets[0],
            "arg1" => offsets.arg_offsets[1],
            "arg2" => offsets.arg_offsets[2],
            "arg3" => offsets.arg_offsets[3],
            "arg4" => offsets.arg_offsets[4],
            "arg5" => offsets.arg_offsets[5],
            "retval" => offsets.retval_offset,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' has unsupported pt_regs register '{}'; expected arg0..arg5 or retval",
                    path_desc, register_name
                )));
            }
        };
        let register_offset = usize::try_from(i32::from(register_offset)).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "pt_regs register '{}' offset is negative",
                register_name
            ))
        })?;

        let regs_ty = MirType::named_kernel_struct_ptr("pt_regs");
        let regs_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(regs_vreg, regs_ty);
        self.emit(MirInst::CallHelper {
            dst: regs_vreg,
            helper: BpfHelper::TaskPtRegs as u32,
            args: vec![MirValue::VReg(base_vreg)],
        });

        let slot_ty = MirType::U64;
        let register_slot =
            self.func
                .alloc_stack_slot(align_to_eight(slot_ty.size()), 8, StackSlotKind::Local);
        self.record_stack_slot_type(register_slot, slot_ty.clone());
        self.emit_trampoline_probe_read_to_slot(
            regs_vreg,
            AddressSpace::Kernel,
            register_offset,
            register_slot,
            &slot_ty,
            path_desc,
        )?;
        self.vreg_type_hints.insert(dst_vreg, slot_ty.clone());
        self.emit(MirInst::LoadSlot {
            dst: dst_vreg,
            slot: register_slot,
            offset: 0,
            ty: slot_ty.clone(),
        });
        Ok(Some(slot_ty))
    }
}
