use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::mir::CtxStoreTarget;

impl<'a> HirToMirLowering<'a> {
    fn ctx_path_member_name(member: &PathMember) -> Result<String, CompileError> {
        match member {
            PathMember::String { val, .. } => Ok(val.clone()),
            PathMember::Int { val, .. } => Ok(format!("arg{}", val)),
        }
    }

    pub(super) fn resolve_ctx_field_from_path(
        &self,
        path: &CellPath,
    ) -> Result<(CtxField, usize), CompileError> {
        let field_name = Self::ctx_path_member_name(&path.members[0])?;
        if field_name == "arg" {
            let Some(arg_member) = path.members.get(1) else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> requires a named BTF parameter".into(),
                ));
            };
            let PathMember::String { val: arg_name, .. } = arg_member else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> requires a named BTF parameter".into(),
                ));
            };
            let Some(ctx) = self.probe_ctx else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> is only available on kernel-BTF-backed contexts".into(),
                ));
            };
            let field = ctx
                .resolve_named_ctx_arg(arg_name)
                .map_err(CompileError::UnsupportedInstruction)?;
            return Ok((field, 2));
        }

        let field = match self.probe_ctx {
            Some(ctx) => ctx.resolve_ctx_field_name(&field_name),
            None => EbpfProgramType::resolve_untyped_ctx_field_name(&field_name),
        }
        .map_err(CompileError::UnsupportedInstruction)?;

        Ok((field, 1))
    }

    fn resolve_ctx_store_target_from_path(
        &self,
        path: &CellPath,
    ) -> Result<CtxStoreTarget, CompileError> {
        let path_desc = Self::typed_value_path_desc(&path.members);
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };
        let (field_name, index) = match path.members.as_slice() {
            [member] => (Self::ctx_path_member_name(member)?, None),
            [member, PathMember::Int { val: index, .. }] => {
                (Self::ctx_path_member_name(member)?, Some(*index))
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' is only supported for sock_ops reply fields, writable cgroup_sockopt scalar fields, and cgroup_sock_addr rewrite fields",
                    path_desc
                )));
            }
        };

        ctx.resolve_ctx_store_target(&field_name, index, &path_desc)
            .map_err(CompileError::UnsupportedInstruction)
    }

    pub(super) fn lower_context_upsert_cell_path(
        &mut self,
        src_dst: RegId,
        path: &CellPath,
        new_value: RegId,
    ) -> Result<(), CompileError> {
        let target = self.resolve_ctx_store_target_from_path(path)?;
        let new_value_vreg = self.get_vreg(new_value);
        let new_value_runtime_ty = self
            .typed_value_runtime_type(new_value, new_value_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires type information for the new value",
                    Self::typed_value_path_desc(&path.members)
                ))
            })?;
        let target_ty = target.value_type();
        let stored_vreg = match new_value_runtime_ty {
            MirType::Bool
            | MirType::I8
            | MirType::U8
            | MirType::I16
            | MirType::U16
            | MirType::I32
            | MirType::U32
            | MirType::I64
            | MirType::U64 => {
                let widened = self.func.alloc_vreg();
                self.vreg_type_hints.insert(widened, target_ty.clone());
                self.emit(MirInst::Copy {
                    dst: widened,
                    src: MirValue::VReg(new_value_vreg),
                });
                widened
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires an integer-compatible scalar value",
                    Self::typed_value_path_desc(&path.members)
                )));
            }
        };
        self.emit(MirInst::StoreCtxField {
            target,
            val: MirValue::VReg(stored_vreg),
            ty: target_ty,
        });
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }
}
