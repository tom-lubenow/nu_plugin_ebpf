use super::{
    CompileError, CtxField, CtxWriteTarget, EbpfProgramType, IngressIfindexContextLayout,
    PacketContextKind, ProbeContext, ProgramTargetKind, ProgramTypeInfo, ProgramValueAccess,
    SocketContextLayout,
};
#[cfg(test)]
use crate::compiler::ctx_field_schema::synthetic_bpf_sock_type;
use crate::compiler::ctx_field_schema::{
    ContextFieldProjectionSpec, ContextFieldTypeSpec, program_type_ctx_field_projection_spec,
    program_type_ctx_field_type_spec, static_ctx_field_projection_spec, static_ctx_field_type_spec,
};
use crate::compiler::hindley_milner::HMType;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::CtxStoreTarget;
#[cfg(test)]
use crate::compiler::mir::MirType;
use crate::kernel_btf::{
    FieldInfo, KernelBtf, TracepointContext, TrampolineFieldProjection, TrampolineFieldSelector,
    TrampolineValueSpec, TypeInfo,
};
use crate::program_spec::ProgramSpec;

impl ProbeContext {
    pub(crate) fn resolve_ctx_field_type_spec(
        probe_ctx: Option<&Self>,
        field: &CtxField,
    ) -> Option<ContextFieldTypeSpec> {
        probe_ctx.map_or_else(
            || Self::static_ctx_field_type_spec(field),
            |ctx| ctx.ctx_field_type_spec(field),
        )
    }

    pub(crate) fn resolve_ctx_field_projection_spec(
        probe_ctx: Option<&Self>,
        field: &CtxField,
    ) -> Option<ContextFieldProjectionSpec> {
        probe_ctx.map_or_else(
            || Self::static_ctx_field_projection_spec(field),
            |ctx| ctx.ctx_field_projection_spec(field),
        )
    }

    pub(crate) fn static_ctx_field_type_spec(field: &CtxField) -> Option<ContextFieldTypeSpec> {
        static_ctx_field_type_spec(field)
    }

    pub(crate) fn static_ctx_field_projection_spec(
        field: &CtxField,
    ) -> Option<ContextFieldProjectionSpec> {
        static_ctx_field_projection_spec(field)
    }

    #[cfg(test)]
    pub(crate) fn synthetic_socket_type() -> MirType {
        synthetic_bpf_sock_type()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn struct_ops_value_type_name(&self) -> Option<&str> {
        self.struct_ops_value_type_name.as_deref()
    }

    pub(crate) fn parsed_program_spec(&self) -> Option<&ProgramSpec> {
        self.program_spec.as_ref()
    }

    pub(crate) fn program_type(&self) -> EbpfProgramType {
        self.parsed_program_spec()
            .map(|spec| spec.program_type())
            .unwrap_or(self.probe_type)
    }

    pub(crate) fn program_info(&self) -> &'static ProgramTypeInfo {
        self.program_type().info()
    }

    pub(crate) fn canonical_prefix(&self) -> &'static str {
        self.program_type().canonical_prefix()
    }

    pub(crate) fn arg_access(&self) -> ProgramValueAccess {
        self.program_type().arg_access()
    }

    pub(crate) fn retval_access(&self) -> ProgramValueAccess {
        self.program_type().retval_access()
    }

    pub(crate) fn uses_btf_trampoline(&self) -> bool {
        self.program_type().uses_btf_trampoline()
    }

    pub(crate) fn uses_raw_tracepoint_args(&self) -> bool {
        self.program_type().uses_raw_tracepoint_args()
    }

    pub(crate) fn supports_ctx_retval(&self) -> bool {
        self.program_type().supports_ctx_retval()
    }

    pub(crate) fn packet_context_kind(&self) -> Option<PacketContextKind> {
        self.parsed_program_spec()
            .and_then(|spec| spec.packet_context_kind())
            .or_else(|| self.probe_type.packet_context_kind())
    }

    pub(crate) fn supports_direct_packet_writes(&self) -> bool {
        self.parsed_program_spec()
            .map(|spec| spec.supports_direct_packet_writes())
            .unwrap_or_else(|| self.probe_type.supports_direct_packet_writes())
    }

    pub(crate) fn socket_family_context_layout(&self) -> Option<SocketContextLayout> {
        self.parsed_program_spec()
            .and_then(|spec| spec.socket_family_context_layout())
            .or_else(|| self.probe_type.socket_family_context_layout())
    }

    pub(crate) fn socket_tuple_context_layout(&self) -> Option<SocketContextLayout> {
        self.parsed_program_spec()
            .and_then(|spec| spec.socket_tuple_context_layout())
            .or_else(|| self.probe_type.socket_tuple_context_layout())
    }

    pub(crate) fn sock_type_context_layout(&self) -> Option<SocketContextLayout> {
        self.parsed_program_spec()
            .and_then(|spec| spec.sock_type_context_layout())
            .or_else(|| self.probe_type.sock_type_context_layout())
    }

    pub(crate) fn protocol_context_layout(&self) -> Option<SocketContextLayout> {
        self.parsed_program_spec()
            .and_then(|spec| spec.protocol_context_layout())
            .or_else(|| self.probe_type.protocol_context_layout())
    }

    pub(crate) fn socket_ref_context_layout(&self) -> Option<SocketContextLayout> {
        self.parsed_program_spec()
            .and_then(|spec| spec.socket_ref_context_layout())
            .or_else(|| self.probe_type.socket_ref_context_layout())
    }

    pub(crate) fn ingress_ifindex_context_layout(&self) -> Option<IngressIfindexContextLayout> {
        self.parsed_program_spec()
            .and_then(|spec| spec.ingress_ifindex_context_layout())
            .or_else(|| self.probe_type.ingress_ifindex_context_layout())
    }

    pub(crate) fn sock_mark_priority_context_layout(&self) -> Option<SocketContextLayout> {
        self.parsed_program_spec()
            .and_then(|spec| spec.sock_mark_priority_context_layout())
            .or_else(|| self.probe_type.sock_mark_priority_context_layout())
    }

    fn require_struct_ops_value_type_name(&self) -> Result<&str, String> {
        self.struct_ops_value_type_name.as_deref().ok_or_else(|| {
            format!(
                "missing struct_ops value type for callback '{}'",
                self.target
            )
        })
    }

    /// Create a new probe context
    pub fn new(probe_type: EbpfProgramType, target: impl Into<String>) -> Self {
        let target = target.into();
        Self {
            probe_type,
            program_spec: ProgramSpec::from_program_type_target(probe_type, &target).ok(),
            target,
            struct_ops_value_type_name: None,
        }
    }

    /// Create a probe context for a `struct_ops` callback.
    pub fn new_struct_ops_callback(
        value_type_name: impl Into<String>,
        callback_name: impl Into<String>,
    ) -> Self {
        let value_type_name = value_type_name.into();
        let callback_name = callback_name.into();
        Self {
            probe_type: EbpfProgramType::StructOps,
            target: callback_name,
            program_spec: Some(ProgramSpec::StructOps {
                value_type_name: value_type_name.clone(),
            }),
            struct_ops_value_type_name: Some(value_type_name),
        }
    }

    /// Create a default probe context for tests or legacy code
    ///
    /// Defaults to kprobe with empty target, which means:
    /// - Not a return probe (retval access will fail)
    /// - Not userspace (read-str defaults to kernel reads)
    pub fn default_for_tests() -> Self {
        let target = String::new();
        Self {
            probe_type: EbpfProgramType::Kprobe,
            target: target.clone(),
            program_spec: ProgramSpec::from_program_type_target(EbpfProgramType::Kprobe, &target)
                .ok(),
            struct_ops_value_type_name: None,
        }
    }

    /// Returns true if this is a return probe
    pub fn is_return_probe(&self) -> bool {
        self.program_type().is_return_probe()
    }

    /// Returns true if this is a userspace probe
    pub fn is_userspace(&self) -> bool {
        self.program_type().is_userspace()
    }

    /// Returns true if this is a tracepoint
    pub fn is_tracepoint(&self) -> bool {
        matches!(
            self.program_type().target_kind(),
            ProgramTargetKind::Tracepoint
        )
    }

    pub(crate) fn ctx_field_type_spec(&self, field: &CtxField) -> Option<ContextFieldTypeSpec> {
        self.ctx_field_access_error(field)
            .is_none()
            .then(|| {
                self.parsed_program_spec()
                    .and_then(|spec| spec.ctx_field_type_spec(field))
                    .or_else(|| program_type_ctx_field_type_spec(self.program_type(), field))
            })
            .flatten()
    }

    pub(crate) fn ctx_field_projection_spec(
        &self,
        field: &CtxField,
    ) -> Option<ContextFieldProjectionSpec> {
        self.ctx_field_access_error(field)
            .is_none()
            .then(|| {
                self.parsed_program_spec()
                    .and_then(|spec| spec.ctx_field_projection_spec(field))
                    .or_else(|| program_type_ctx_field_projection_spec(self.program_type(), field))
            })
            .flatten()
    }

    /// Get tracepoint category and name
    ///
    /// For tracepoint "syscalls/sys_enter_openat", returns Some(("syscalls", "sys_enter_openat"))
    pub fn tracepoint_parts(&self) -> Option<(String, String)> {
        match self.parsed_program_spec()? {
            ProgramSpec::Tracepoint { category, name } => Some((category.clone(), name.clone())),
            _ => None,
        }
    }

    pub(crate) fn btf_context_label(&self) -> String {
        match self.program_type() {
            EbpfProgramType::StructOps => format!(
                "struct_ops {}.{}",
                self.struct_ops_value_type_name
                    .as_deref()
                    .unwrap_or("<unknown>"),
                self.target
            ),
            EbpfProgramType::TpBtf => format!("tp_btf:{}", self.target),
            EbpfProgramType::Lsm => format!("lsm:{}", self.target),
            _ => format!("{}:{}", self.program_type().section_prefix(), self.target),
        }
    }

    pub(crate) fn btf_arg_unavailable_error(&self, arg_idx: usize) -> String {
        format!(
            "ctx.arg{} is not available on {}",
            arg_idx,
            self.btf_context_label()
        )
    }

    pub(crate) fn btf_arg_name_invalid_error(&self, arg_name: &str) -> String {
        format!(
            "ctx.arg.{} is not a valid argument name for {}",
            arg_name,
            self.btf_context_label()
        )
    }

    pub(crate) fn btf_ret_unavailable_error(&self) -> String {
        format!(
            "ctx.retval is not available on fexit:{} because the target returns void",
            self.target
        )
    }

    pub(crate) fn btf_arg_index_by_name(&self, arg_name: &str) -> Result<Option<usize>, String> {
        if !self.uses_btf_trampoline() {
            return Ok(None);
        }

        let btf = KernelBtf::get();
        match self.program_type() {
            EbpfProgramType::StructOps => {
                let value_type_name = self.require_struct_ops_value_type_name()?;
                btf.struct_ops_callback_arg_index_by_name(value_type_name, &self.target, arg_name)
                    .map_err(|e| {
                        format!(
                            "failed to resolve ctx.arg.{} for struct_ops {}.{}: {}",
                            arg_name, value_type_name, self.target, e
                        )
                    })
            }
            EbpfProgramType::TpBtf => btf
                .tp_btf_arg_index_by_name(&self.target, arg_name)
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg.{} for tp_btf:{}: {}",
                        arg_name, self.target, e
                    )
                }),
            EbpfProgramType::Lsm => btf
                .lsm_hook_arg_index_by_name(&self.target, arg_name)
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg.{} for lsm:{}: {}",
                        arg_name, self.target, e
                    )
                }),
            _ => btf
                .function_trampoline_arg_index_by_name(&self.target, arg_name)
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg.{} for {}:{}: {}",
                        arg_name,
                        self.program_type().section_prefix(),
                        self.target,
                        e
                    )
                }),
        }
    }

    pub(crate) fn btf_arg_spec(
        &self,
        arg_idx: usize,
    ) -> Result<Option<TrampolineValueSpec>, String> {
        if !self.uses_btf_trampoline() {
            return Ok(None);
        }

        let btf = KernelBtf::get();
        match self.program_type() {
            EbpfProgramType::StructOps => {
                let value_type_name = self.require_struct_ops_value_type_name()?;
                btf.struct_ops_callback_arg(value_type_name, &self.target, arg_idx)
                    .map_err(|e| {
                        format!(
                            "failed to resolve ctx.arg{} for struct_ops {}.{}: {}",
                            arg_idx, value_type_name, self.target, e
                        )
                    })
            }
            EbpfProgramType::TpBtf => btf.tp_btf_arg(&self.target, arg_idx).map_err(|e| {
                format!(
                    "failed to resolve ctx.arg{} for tp_btf:{}: {}",
                    arg_idx, self.target, e
                )
            }),
            EbpfProgramType::Lsm => btf.lsm_hook_arg(&self.target, arg_idx).map_err(|e| {
                format!(
                    "failed to resolve ctx.arg{} for lsm:{}: {}",
                    arg_idx, self.target, e
                )
            }),
            _ => btf
                .function_trampoline_arg(&self.target, arg_idx)
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg{} for {}:{}: {}",
                        arg_idx,
                        self.program_type().section_prefix(),
                        self.target,
                        e
                    )
                }),
        }
    }

    pub(crate) fn btf_arg_type_info(&self, arg_idx: usize) -> Result<Option<TypeInfo>, String> {
        if !self.uses_btf_trampoline() {
            return Ok(None);
        }

        let btf = KernelBtf::get();
        match self.program_type() {
            EbpfProgramType::StructOps => {
                let value_type_name = self.require_struct_ops_value_type_name()?;
                btf.struct_ops_callback_arg_type_info(value_type_name, &self.target, arg_idx)
                    .map_err(|e| {
                        format!(
                            "failed to resolve ctx.arg{} type for struct_ops {}.{}: {}",
                            arg_idx, value_type_name, self.target, e
                        )
                    })
            }
            EbpfProgramType::TpBtf => {
                btf.tp_btf_arg_type_info(&self.target, arg_idx)
                    .map_err(|e| {
                        format!(
                            "failed to resolve ctx.arg{} type for tp_btf:{}: {}",
                            arg_idx, self.target, e
                        )
                    })
            }
            EbpfProgramType::Lsm => {
                btf.lsm_hook_arg_type_info(&self.target, arg_idx)
                    .map_err(|e| {
                        format!(
                            "failed to resolve ctx.arg{} type for lsm:{}: {}",
                            arg_idx, self.target, e
                        )
                    })
            }
            _ => btf
                .function_trampoline_arg_type_info(&self.target, arg_idx)
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg{} type for {}:{}: {}",
                        arg_idx,
                        self.program_type().section_prefix(),
                        self.target,
                        e
                    )
                }),
        }
    }

    pub(crate) fn btf_arg_field_projection(
        &self,
        arg_idx: usize,
        field_path: &[TrampolineFieldSelector],
        path_desc: &str,
    ) -> Result<Option<TrampolineFieldProjection>, String> {
        if !self.uses_btf_trampoline() {
            return Ok(None);
        }

        let btf = KernelBtf::get();
        match self.program_type() {
            EbpfProgramType::StructOps => {
                let value_type_name = self.require_struct_ops_value_type_name()?;
                btf.struct_ops_callback_arg_field(
                    value_type_name,
                    &self.target,
                    arg_idx,
                    field_path,
                )
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg{}.{} for struct_ops {}.{}: {}",
                        arg_idx, path_desc, value_type_name, self.target, e
                    )
                })
            }
            EbpfProgramType::TpBtf => btf
                .tp_btf_arg_field(&self.target, arg_idx, field_path)
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg{}.{} for tp_btf:{}: {}",
                        arg_idx, path_desc, self.target, e
                    )
                }),
            EbpfProgramType::Lsm => btf
                .lsm_hook_arg_field(&self.target, arg_idx, field_path)
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg{}.{} for lsm:{}: {}",
                        arg_idx, path_desc, self.target, e
                    )
                }),
            _ => btf
                .function_trampoline_arg_field(&self.target, arg_idx, field_path)
                .map_err(|e| {
                    format!(
                        "failed to resolve ctx.arg{}.{} for {}:{}: {}",
                        arg_idx,
                        path_desc,
                        self.program_type().section_prefix(),
                        self.target,
                        e
                    )
                }),
        }
    }

    pub(crate) fn btf_ret_spec(&self) -> Result<Option<TrampolineValueSpec>, String> {
        if !matches!(self.retval_access(), ProgramValueAccess::Trampoline) {
            return Ok(None);
        }

        KernelBtf::get()
            .function_trampoline_ret(&self.target)
            .map_err(|e| {
                format!(
                    "failed to resolve ctx.retval for fexit:{}: {}",
                    self.target, e
                )
            })
    }

    pub(crate) fn btf_ret_type_info(&self) -> Result<Option<TypeInfo>, String> {
        if !matches!(self.retval_access(), ProgramValueAccess::Trampoline) {
            return Ok(None);
        }

        KernelBtf::get()
            .function_trampoline_ret_type_info(&self.target)
            .map_err(|e| {
                format!(
                    "failed to resolve ctx.retval type for fexit:{}: {}",
                    self.target, e
                )
            })
    }

    pub(crate) fn tracepoint_field_type_info(
        &self,
        field_name: &str,
    ) -> Result<Option<TypeInfo>, String> {
        let Some(field_info) = self.tracepoint_field_info(field_name)? else {
            return Ok(None);
        };
        Ok(Some(field_info.type_info))
    }

    pub(crate) fn tracepoint_context(&self) -> Result<Option<TracepointContext>, String> {
        let Some((category, tp_name)) = self.tracepoint_parts() else {
            return Ok(None);
        };
        KernelBtf::get()
            .get_tracepoint_context(&category, &tp_name)
            .map(Some)
            .map_err(|e| {
                format!(
                    "failed to resolve tracepoint context for tracepoint:{}/{}: {}",
                    category, tp_name, e
                )
            })
    }

    pub(crate) fn tracepoint_field_info(
        &self,
        field_name: &str,
    ) -> Result<Option<FieldInfo>, String> {
        let Some(trace_ctx) = self.tracepoint_context()? else {
            return Ok(None);
        };
        Ok(trace_ctx.get_field(field_name).cloned())
    }

    fn tracepoint_context_or_error(&self) -> Result<TracepointContext, CompileError> {
        let (category, tp_name) =
            self.tracepoint_parts()
                .ok_or_else(|| CompileError::TracepointContextError {
                    category: "unknown".into(),
                    name: self.target.clone(),
                    reason: "Invalid tracepoint format. Expected 'category/name'".into(),
                })?;
        KernelBtf::get()
            .get_tracepoint_context(&category, &tp_name)
            .map_err(|e| CompileError::TracepointContextError {
                category,
                name: tp_name,
                reason: e.to_string(),
            })
    }

    pub(crate) fn tracepoint_field_info_or_error(
        &self,
        field_name: &str,
    ) -> Result<FieldInfo, CompileError> {
        let trace_ctx = self.tracepoint_context_or_error()?;
        trace_ctx.get_field(field_name).cloned().ok_or_else(|| {
            CompileError::TracepointFieldNotFound {
                field: field_name.to_string(),
                available: trace_ctx.field_names().join(", "),
            }
        })
    }

    pub(crate) fn ctx_field_type_info(&self, field: &CtxField) -> Result<Option<TypeInfo>, String> {
        match field {
            CtxField::Arg(idx) if self.uses_btf_trampoline() => {
                self.btf_arg_type_info(*idx as usize)
            }
            CtxField::RetVal if matches!(self.retval_access(), ProgramValueAccess::Trampoline) => {
                self.btf_ret_type_info()
            }
            CtxField::TracepointField(name) => self.tracepoint_field_type_info(name),
            _ => Ok(None),
        }
    }

    pub(crate) fn btf_ret_field_projection(
        &self,
        field_path: &[TrampolineFieldSelector],
        path_desc: &str,
    ) -> Result<Option<TrampolineFieldProjection>, String> {
        if !matches!(self.retval_access(), ProgramValueAccess::Trampoline) {
            return Ok(None);
        }

        KernelBtf::get()
            .function_trampoline_ret_field(&self.target, field_path)
            .map_err(|e| {
                format!(
                    "failed to resolve ctx.retval.{} for fexit:{}: {}",
                    path_desc, self.target, e
                )
            })
    }

    pub(crate) fn main_function_expected_return_type(&self) -> Result<Option<HMType>, String> {
        if self.program_type() != EbpfProgramType::StructOps {
            return Ok(Some(HMType::I64));
        }

        let value_type_name = self.require_struct_ops_value_type_name()?;
        let ret_type = KernelBtf::get()
            .struct_ops_callback_ret_type_info(value_type_name, &self.target)
            .map_err(|err| {
                format!(
                    "failed to resolve return type for struct_ops {}.{}: {}",
                    value_type_name, self.target, err
                )
            })?;

        match ret_type {
            None | Some(TypeInfo::Void) => Ok(None),
            Some(TypeInfo::Int { size, signed }) => Ok(Some(match (size, signed) {
                (1, false) => HMType::Bool,
                (1, true) => HMType::I8,
                (2, false) => HMType::U16,
                (2, true) => HMType::I16,
                (4, false) => HMType::U32,
                (4, true) => HMType::I32,
                (8, false) => HMType::U64,
                (8, true) => HMType::I64,
                _ => {
                    return Err(format!(
                        "struct_ops {}.{} returns an unsupported integer width {}",
                        value_type_name, self.target, size
                    ));
                }
            })),
            Some(TypeInfo::Ptr { .. }) => Ok(Some(HMType::I64)),
            Some(TypeInfo::Struct { .. }) | Some(TypeInfo::Array { .. }) => Err(format!(
                "struct_ops {}.{} returns an aggregate type, which is not supported yet",
                value_type_name, self.target
            )),
            Some(TypeInfo::Unknown) => Err(format!(
                "struct_ops {}.{} returns an unsupported type",
                value_type_name, self.target
            )),
        }
    }

    pub(crate) fn resolve_ctx_field_name(&self, field_name: &str) -> Result<CtxField, String> {
        self.parsed_program_spec().map_or_else(
            || self.program_type().resolve_ctx_field_name(field_name),
            |spec| spec.resolve_ctx_field_name(field_name),
        )
    }

    pub(crate) fn resolve_named_ctx_arg(&self, arg_name: &str) -> Result<CtxField, String> {
        if !self.uses_btf_trampoline() {
            return Err("ctx.arg.<name> is only available on kernel-BTF-backed contexts".into());
        }

        let Some(arg_idx) = self.btf_arg_index_by_name(arg_name)? else {
            return Err(self.btf_arg_name_invalid_error(arg_name));
        };
        let arg_idx = u8::try_from(arg_idx).map_err(|_| {
            format!(
                "ctx.arg.{} resolved to unsupported parameter index {}",
                arg_name, arg_idx
            )
        })?;

        Ok(CtxField::Arg(arg_idx))
    }

    pub(crate) fn resolve_ctx_store_target(
        &self,
        field_name: &str,
        index: Option<usize>,
    ) -> Result<CtxStoreTarget, String> {
        let parsed_program_spec = self.parsed_program_spec();
        if let Some(result) = parsed_program_spec
            .and_then(|spec| spec.resolve_special_ctx_store_target(field_name, index))
        {
            return result;
        }

        let field = self.resolve_ctx_field_name(field_name)?;
        self.validate_ctx_field_access(&field)
            .map_err(|err| err.to_string())?;

        if let Some(result) = parsed_program_spec
            .and_then(|spec| spec.resolve_ctx_store_target_for_field(&field, index))
        {
            return result;
        }

        Err(format!("ctx.{} is read-only", field.display_name()))
    }

    pub(crate) fn resolve_ctx_write_target(
        &self,
        field_name: &str,
        index: Option<usize>,
    ) -> Result<CtxWriteTarget, String> {
        if let Some(result) = self
            .parsed_program_spec()
            .and_then(|spec| spec.resolve_special_ctx_write_target(field_name, index))
        {
            return result;
        }

        self.resolve_ctx_store_target(field_name, index)
            .map(CtxWriteTarget::StoreField)
    }

    pub(crate) fn ctx_store_target_error(&self, target: &CtxStoreTarget) -> Option<String> {
        self.parsed_program_spec()
            .and_then(|spec| spec.ctx_store_target_error(target))
            .or_else(|| self.program_type().base_ctx_store_target_error(target))
    }

    pub(crate) fn validate_ctx_store_target(
        &self,
        target: &CtxStoreTarget,
    ) -> Result<(), CompileError> {
        if let Some(message) = self.ctx_store_target_error(target) {
            return Err(CompileError::UnsupportedInstruction(message));
        }
        Ok(())
    }

    /// Returns a user-facing error message when a context field is not valid
    /// for this program type.
    pub fn ctx_field_access_error(&self, field: &CtxField) -> Option<String> {
        self.parsed_program_spec()
            .and_then(|spec| spec.ctx_field_access_error(field))
            .or_else(|| self.program_type().base_ctx_field_access_error(field))
    }

    pub fn validate_ctx_field_access(&self, field: &CtxField) -> Result<(), CompileError> {
        if let Some(message) = self.ctx_field_access_error(field) {
            return Err(CompileError::UnsupportedInstruction(message));
        }
        Ok(())
    }

    pub(crate) fn validate_load_ctx_field(&self, field: &CtxField) -> Result<(), CompileError> {
        self.validate_ctx_field_access(field)?;
        match field {
            CtxField::Arg(idx) if matches!(self.arg_access(), ProgramValueAccess::PtRegs) => {
                let offsets = KernelBtf::get().pt_regs_offsets().map_err(|e| {
                    CompileError::UnsupportedInstruction(format!(
                        "pt_regs argument access unavailable: {e}"
                    ))
                })?;
                if usize::from(*idx) >= offsets.arg_offsets.len() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Argument index {} out of range",
                        idx
                    )));
                }
            }
            CtxField::Arg(idx)
                if matches!(self.arg_access(), ProgramValueAccess::RawTracepoint) =>
            {
                let byte_offset = usize::from(*idx).checked_mul(8).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "raw tracepoint arg offset overflow".into(),
                    )
                })?;
                i16::try_from(byte_offset).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "raw tracepoint arg index {} is too large",
                        idx
                    ))
                })?;
            }
            CtxField::Arg(idx) if self.uses_btf_trampoline() => {
                if self
                    .btf_arg_spec(*idx as usize)
                    .map_err(CompileError::UnsupportedInstruction)?
                    .is_none()
                {
                    return Err(CompileError::UnsupportedInstruction(
                        self.btf_arg_unavailable_error(*idx as usize),
                    ));
                }
            }
            CtxField::RetVal if matches!(self.retval_access(), ProgramValueAccess::PtRegs) => {
                KernelBtf::get().pt_regs_offsets().map_err(|e| {
                    CompileError::UnsupportedInstruction(format!(
                        "pt_regs return value access unavailable: {e}"
                    ))
                })?;
            }
            CtxField::RetVal if matches!(self.retval_access(), ProgramValueAccess::Trampoline) => {
                if self
                    .btf_ret_spec()
                    .map_err(CompileError::UnsupportedInstruction)?
                    .is_none()
                {
                    return Err(CompileError::UnsupportedInstruction(
                        self.btf_ret_unavailable_error(),
                    ));
                }
            }
            CtxField::TracepointField(name) => {
                self.tracepoint_field_info_or_error(name)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns a user-facing error message when a helper is not valid
    /// for this program type or attach context.
    pub fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        self.parsed_program_spec()
            .and_then(|spec| spec.helper_call_error(helper))
            .or_else(|| self.program_type().helper_call_error(helper))
    }

    pub(crate) fn helper_zero_arg_requirement(
        &self,
        helper: BpfHelper,
    ) -> Option<(usize, &'static str)> {
        self.program_type().helper_zero_arg_requirement(helper)
    }

    fn sched_ext_callback(&self) -> Option<&str> {
        if self.program_type() != EbpfProgramType::StructOps {
            return None;
        }
        if self.struct_ops_value_type_name.as_deref() != Some("sched_ext_ops") {
            return None;
        }
        Some(self.target.as_str())
    }

    fn sched_ext_callback_is_sleepable(callback: &str) -> bool {
        super::struct_ops_callback_is_sleepable("sched_ext_ops", callback)
    }

    fn sched_ext_kfunc_allowed_callbacks(kfunc: &str) -> Option<&'static [&'static str]> {
        match kfunc {
            "scx_bpf_dispatch_nr_slots"
            | "scx_bpf_dsq_move_to_local"
            | "scx_bpf_dispatch_cancel"
            | "scx_bpf_dsq_move"
            | "scx_bpf_dsq_move_vtime"
            | "scx_bpf_dsq_move_set_slice"
            | "scx_bpf_dsq_move_set_vtime" => Some(&["dispatch"]),
            "scx_bpf_reenqueue_local" => Some(&["cpu_release"]),
            "scx_bpf_select_cpu_dfl" | "scx_bpf_select_cpu_and" => Some(&["select_cpu", "enqueue"]),
            "scx_bpf_dsq_insert" | "scx_bpf_dsq_insert_vtime" => {
                Some(&["select_cpu", "enqueue", "dispatch"])
            }
            _ => None,
        }
    }

    fn format_sched_ext_callback_list(callbacks: &[&str]) -> String {
        match callbacks {
            [] => String::new(),
            [only] => format!("sched_ext_ops.{only}"),
            [left, right] => format!("sched_ext_ops.{left} or sched_ext_ops.{right}"),
            _ => {
                let mut names = callbacks
                    .iter()
                    .map(|callback| format!("sched_ext_ops.{callback}"))
                    .collect::<Vec<_>>();
                let last = names.pop().unwrap();
                format!("{}, or {}", names.join(", "), last)
            }
        }
    }

    /// Returns a user-facing error message when a kfunc is not valid
    /// for this program type or attach context.
    pub fn kfunc_call_error(&self, kfunc: &str) -> Option<String> {
        let active_callback = self.sched_ext_callback()?;
        if kfunc == "scx_bpf_create_dsq" && !Self::sched_ext_callback_is_sleepable(active_callback)
        {
            return Some(format!(
                "kfunc '{}' is only valid in sleepable sched_ext_ops callbacks, not sched_ext_ops.{}",
                kfunc, active_callback
            ));
        }
        let allowed_callbacks = Self::sched_ext_kfunc_allowed_callbacks(kfunc)?;
        if allowed_callbacks.contains(&active_callback) {
            return None;
        }
        let allowed = Self::format_sched_ext_callback_list(allowed_callbacks);
        Some(format!(
            "kfunc '{}' is only valid in {}, not sched_ext_ops.{}",
            kfunc, allowed, active_callback
        ))
    }

    /// Returns a user-facing error message when a socket projection member is
    /// not valid for this program type or attach context.
    pub fn socket_projection_access_error(&self, member_name: &str) -> Option<String> {
        self.parsed_program_spec()
            .and_then(|spec| spec.socket_projection_access_error(member_name))
    }
}
