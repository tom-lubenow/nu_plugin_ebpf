use super::{
    CompileError, CtxField, CtxWriteTarget, EbpfProgramType, ProbeContext, ProgramTargetKind,
    ProgramValueAccess,
};
use crate::compiler::context_schema::{
    resolve_probe_ctx_field_name, static_ctx_field_access_error,
};
use crate::compiler::hindley_milner::HMType;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::CtxStoreTarget;
use crate::kernel_btf::{
    KernelBtf, TrampolineFieldProjection, TrampolineFieldSelector, TrampolineValueSpec, TypeInfo,
};
use crate::program_spec::{
    CgroupSockAddrTarget, CgroupSockTarget, CgroupSockoptTarget, ProgramSpec, TcTarget,
};

impl ProbeContext {
    pub(crate) fn parsed_program_spec(&self) -> Option<ProgramSpec> {
        ProgramSpec::from_program_type_target(self.probe_type, &self.target).ok()
    }

    pub(crate) fn tc_target(&self) -> Option<TcTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::Tc { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn tc_is_ingress(&self) -> bool {
        self.tc_target().is_some_and(|target| target.is_ingress())
    }

    pub(crate) fn cgroup_sock_target(&self) -> Option<CgroupSockTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::CgroupSock { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn cgroup_sock_is_post_bind(&self) -> bool {
        self.cgroup_sock_target()
            .is_some_and(|target| target.is_post_bind())
    }

    fn cgroup_sock_addr_target(&self) -> Option<CgroupSockAddrTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::CgroupSockAddr { target } => Some(target),
            _ => None,
        }
    }

    fn cgroup_sock_addr_is_ipv4(&self) -> bool {
        self.cgroup_sock_addr_target()
            .is_some_and(|target| target.is_ipv4())
    }

    fn cgroup_sock_addr_is_ipv6(&self) -> bool {
        self.cgroup_sock_addr_target()
            .is_some_and(|target| target.is_ipv6())
    }

    fn cgroup_sock_addr_has_msg_source(&self) -> bool {
        self.cgroup_sock_addr_target()
            .is_some_and(|target| target.has_msg_source())
    }

    fn cgroup_sock_addr_is_connect(&self) -> bool {
        self.cgroup_sock_addr_target()
            .is_some_and(|target| target.is_connect())
    }

    fn cgroup_sockopt_target(&self) -> Option<CgroupSockoptTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::CgroupSockopt { target } => Some(target),
            _ => None,
        }
    }

    fn cgroup_sockopt_is_get(&self) -> bool {
        self.cgroup_sockopt_target()
            .is_some_and(|target| target.is_get())
    }

    fn cgroup_sockopt_store_field_error(&self, field: &CtxField) -> Option<String> {
        match field {
            CtxField::SockoptLevel | CtxField::SockoptOptname => {
                if let Some(message) = self.ctx_field_access_error(field) {
                    return Some(message);
                }
                if self.cgroup_sockopt_is_get() {
                    Some(format!(
                        "ctx.{} is only writable on cgroup_sockopt:set hooks",
                        field.display_name()
                    ))
                } else {
                    None
                }
            }
            CtxField::SockoptOptlen | CtxField::SockoptRetval => self.ctx_field_access_error(field),
            _ => None,
        }
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
        Self {
            probe_type,
            target: target.into(),
            struct_ops_value_type_name: None,
        }
    }

    /// Create a probe context for a `struct_ops` callback.
    pub fn new_struct_ops_callback(
        value_type_name: impl Into<String>,
        callback_name: impl Into<String>,
    ) -> Self {
        Self {
            probe_type: EbpfProgramType::StructOps,
            target: callback_name.into(),
            struct_ops_value_type_name: Some(value_type_name.into()),
        }
    }

    /// Create a default probe context for tests or legacy code
    ///
    /// Defaults to kprobe with empty target, which means:
    /// - Not a return probe (retval access will fail)
    /// - Not userspace (read-str defaults to kernel reads)
    pub fn default_for_tests() -> Self {
        Self {
            probe_type: EbpfProgramType::Kprobe,
            target: String::new(),
            struct_ops_value_type_name: None,
        }
    }

    /// Returns true if this is a return probe
    pub fn is_return_probe(&self) -> bool {
        self.probe_type.is_return_probe()
    }

    /// Returns true if this is a userspace probe
    pub fn is_userspace(&self) -> bool {
        self.probe_type.is_userspace()
    }

    /// Returns true if this is a tracepoint
    pub fn is_tracepoint(&self) -> bool {
        matches!(self.probe_type.target_kind(), ProgramTargetKind::Tracepoint)
    }

    /// Get tracepoint category and name
    ///
    /// For tracepoint "syscalls/sys_enter_openat", returns Some(("syscalls", "sys_enter_openat"))
    pub fn tracepoint_parts(&self) -> Option<(String, String)> {
        match self.parsed_program_spec()? {
            ProgramSpec::Tracepoint { category, name } => Some((category, name)),
            _ => None,
        }
    }

    pub(crate) fn btf_context_label(&self) -> String {
        match self.probe_type {
            EbpfProgramType::StructOps => format!(
                "struct_ops {}.{}",
                self.struct_ops_value_type_name
                    .as_deref()
                    .unwrap_or("<unknown>"),
                self.target
            ),
            EbpfProgramType::TpBtf => format!("tp_btf:{}", self.target),
            EbpfProgramType::Lsm => format!("lsm:{}", self.target),
            _ => format!("{}:{}", self.probe_type.section_prefix(), self.target),
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
        if !self.probe_type.uses_btf_trampoline() {
            return Ok(None);
        }

        let btf = KernelBtf::get();
        match self.probe_type {
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
                        self.probe_type.section_prefix(),
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
        if !self.probe_type.uses_btf_trampoline() {
            return Ok(None);
        }

        let btf = KernelBtf::get();
        match self.probe_type {
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
                        self.probe_type.section_prefix(),
                        self.target,
                        e
                    )
                }),
        }
    }

    pub(crate) fn btf_arg_type_info(&self, arg_idx: usize) -> Result<Option<TypeInfo>, String> {
        if !self.probe_type.uses_btf_trampoline() {
            return Ok(None);
        }

        let btf = KernelBtf::get();
        match self.probe_type {
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
                        self.probe_type.section_prefix(),
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
        if !self.probe_type.uses_btf_trampoline() {
            return Ok(None);
        }

        let btf = KernelBtf::get();
        match self.probe_type {
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
                        self.probe_type.section_prefix(),
                        self.target,
                        e
                    )
                }),
        }
    }

    pub(crate) fn btf_ret_spec(&self) -> Result<Option<TrampolineValueSpec>, String> {
        if !matches!(
            self.probe_type.retval_access(),
            ProgramValueAccess::Trampoline
        ) {
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
        if !matches!(
            self.probe_type.retval_access(),
            ProgramValueAccess::Trampoline
        ) {
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

    pub(crate) fn btf_ret_field_projection(
        &self,
        field_path: &[TrampolineFieldSelector],
        path_desc: &str,
    ) -> Result<Option<TrampolineFieldProjection>, String> {
        if !matches!(
            self.probe_type.retval_access(),
            ProgramValueAccess::Trampoline
        ) {
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
        if self.probe_type != EbpfProgramType::StructOps {
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
        resolve_probe_ctx_field_name(self, field_name)
    }

    pub(crate) fn resolve_named_ctx_arg(&self, arg_name: &str) -> Result<CtxField, String> {
        if !self.probe_type.uses_btf_trampoline() {
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
        _path_desc: &str,
    ) -> Result<CtxStoreTarget, String> {
        let word_index = |field_name: &str, index: usize| -> Result<u8, String> {
            let index = u8::try_from(index)
                .map_err(|_| format!("ctx.{field_name} index must be in 0..=3, got {index}"))?;
            if index >= 4 {
                return Err(format!(
                    "ctx.{field_name} index must be in 0..=3, got {index}"
                ));
            }
            Ok(index)
        };
        match (field_name, index) {
            ("reply", None) if self.probe_type == EbpfProgramType::SockOps => {
                return Ok(CtxStoreTarget::SockOpsReply);
            }
            ("reply", Some(_)) if self.probe_type == EbpfProgramType::SockOps => {
                return Err("ctx.reply does not support indexed assignment".into());
            }
            ("replylong", Some(index)) if self.probe_type == EbpfProgramType::SockOps => {
                let index = u8::try_from(index)
                    .map_err(|_| format!("ctx.replylong index must be in 0..=3, got {}", index))?;
                if index >= 4 {
                    return Err(format!(
                        "ctx.replylong index must be in 0..=3, got {}",
                        index
                    ));
                }
                return Ok(CtxStoreTarget::SockOpsReplyLong(index));
            }
            ("replylong", None) if self.probe_type == EbpfProgramType::SockOps => {
                return Err(
                    "ctx.replylong assignment requires a fixed index, e.g. $ctx.replylong.0 = ..."
                        .into(),
                );
            }
            _ => {}
        }

        let field = self.resolve_ctx_field_name(field_name)?;
        self.validate_ctx_field_access(&field)
            .map_err(|err| err.to_string())?;

        match (&field, index) {
            (CtxField::SysctlFilePos, None) => Ok(CtxStoreTarget::SysctlFilePos),
            (CtxField::SysctlFilePos, Some(_)) => {
                Err("ctx.file_pos does not support indexed assignment".into())
            }
            (CtxField::SockoptRetval, None) => {
                if let Some(err) = self.cgroup_sockopt_store_field_error(&CtxField::SockoptRetval) {
                    return Err(err);
                }
                Ok(CtxStoreTarget::SockoptRetval)
            }
            (CtxField::SockoptRetval, Some(_)) => {
                Err("ctx.sockopt_retval does not support indexed assignment".into())
            }
            (CtxField::SockoptLevel, None) => {
                if let Some(err) = self.cgroup_sockopt_store_field_error(&CtxField::SockoptLevel) {
                    return Err(err);
                }
                Ok(CtxStoreTarget::SockoptLevel)
            }
            (CtxField::SockoptLevel, Some(_)) => {
                Err("ctx.level does not support indexed assignment".into())
            }
            (CtxField::SockoptOptname, None) => {
                if let Some(err) = self.cgroup_sockopt_store_field_error(&CtxField::SockoptOptname)
                {
                    return Err(err);
                }
                Ok(CtxStoreTarget::SockoptOptname)
            }
            (CtxField::SockoptOptname, Some(_)) => {
                Err("ctx.optname does not support indexed assignment".into())
            }
            (CtxField::SockoptOptlen, None) => {
                if let Some(err) = self.cgroup_sockopt_store_field_error(&CtxField::SockoptOptlen) {
                    return Err(err);
                }
                Ok(CtxStoreTarget::SockoptOptlen)
            }
            (CtxField::SockoptOptlen, Some(_)) => {
                Err("ctx.optlen does not support indexed assignment".into())
            }
            (CtxField::UserIp4, None) => Ok(CtxStoreTarget::CgroupSockAddrUserIp4),
            (CtxField::UserIp4, Some(_)) => {
                Err("ctx.user_ip4 does not support indexed assignment".into())
            }
            (CtxField::UserIp6, Some(index)) => Ok(CtxStoreTarget::CgroupSockAddrUserIp6Word(
                word_index("user_ip6", index)?,
            )),
            (CtxField::UserIp6, None) => Err(
                "ctx.user_ip6 assignment requires a fixed index, e.g. $ctx.user_ip6.0 = ...".into(),
            ),
            (CtxField::UserPort, None) => Ok(CtxStoreTarget::CgroupSockAddrUserPort),
            (CtxField::UserPort, Some(_)) => {
                Err("ctx.user_port does not support indexed assignment".into())
            }
            (CtxField::MsgSrcIp4, None) => Ok(CtxStoreTarget::CgroupSockAddrMsgSrcIp4),
            (CtxField::MsgSrcIp4, Some(_)) => {
                Err("ctx.msg_src_ip4 does not support indexed assignment".into())
            }
            (CtxField::MsgSrcIp6, Some(index)) => Ok(CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(
                word_index("msg_src_ip6", index)?,
            )),
            (CtxField::MsgSrcIp6, None) => Err(
                "ctx.msg_src_ip6 assignment requires a fixed index, e.g. $ctx.msg_src_ip6.0 = ..."
                    .into(),
            ),
            _ => Err(format!("ctx.{} is read-only", field.display_name())),
        }
    }

    pub(crate) fn resolve_ctx_write_target(
        &self,
        field_name: &str,
        index: Option<usize>,
        path_desc: &str,
    ) -> Result<CtxWriteTarget, String> {
        if field_name == "optval" {
            self.validate_ctx_field_access(&CtxField::SockoptOptval)
                .map_err(|err| err.to_string())?;
            self.validate_ctx_field_access(&CtxField::SockoptOptvalEnd)
                .map_err(|err| err.to_string())?;
            let Some(index) = index else {
                return Err(
                    "ctx.optval assignment requires a fixed index, e.g. $ctx.optval.0 = ..."
                        .to_string(),
                );
            };
            return Ok(CtxWriteTarget::SockoptOptvalByte(index));
        }

        self.resolve_ctx_store_target(field_name, index, path_desc)
            .map(CtxWriteTarget::StoreField)
    }

    pub(crate) fn ctx_store_target_error(&self, target: &CtxStoreTarget) -> Option<String> {
        match target {
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => {
                if self.probe_type != EbpfProgramType::SockOps {
                    Some(
                        "writable sock_ops reply fields are only supported on sock_ops programs"
                            .to_string(),
                    )
                } else {
                    None
                }
            }
            CtxStoreTarget::SysctlFilePos => self.ctx_field_access_error(&CtxField::SysctlFilePos),
            CtxStoreTarget::SockoptLevel => {
                self.cgroup_sockopt_store_field_error(&CtxField::SockoptLevel)
            }
            CtxStoreTarget::SockoptOptname => {
                self.cgroup_sockopt_store_field_error(&CtxField::SockoptOptname)
            }
            CtxStoreTarget::SockoptOptlen => {
                self.cgroup_sockopt_store_field_error(&CtxField::SockoptOptlen)
            }
            CtxStoreTarget::SockoptRetval => {
                self.cgroup_sockopt_store_field_error(&CtxField::SockoptRetval)
            }
            CtxStoreTarget::CgroupSockAddrUserIp4 => {
                self.ctx_field_access_error(&CtxField::UserIp4)
            }
            CtxStoreTarget::CgroupSockAddrUserIp6Word(_) => {
                self.ctx_field_access_error(&CtxField::UserIp6)
            }
            CtxStoreTarget::CgroupSockAddrUserPort => {
                self.ctx_field_access_error(&CtxField::UserPort)
            }
            CtxStoreTarget::CgroupSockAddrMsgSrcIp4 => {
                self.ctx_field_access_error(&CtxField::MsgSrcIp4)
            }
            CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_) => {
                self.ctx_field_access_error(&CtxField::MsgSrcIp6)
            }
        }
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
        if let Some(message) = static_ctx_field_access_error(self, field) {
            return Some(message);
        }
        let program_type = self.probe_type;

        match field {
            CtxField::UserIp4 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.user_ip4 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::UserIp4 if !self.cgroup_sock_addr_is_ipv4() => Some(
                "ctx.user_ip4 is only available on IPv4 cgroup_sock_addr hooks (*4)".to_string(),
            ),
            CtxField::UserIp6 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.user_ip6 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::UserIp6 if !self.cgroup_sock_addr_is_ipv6() => Some(
                "ctx.user_ip6 is only available on IPv6 cgroup_sock_addr hooks (*6)".to_string(),
            ),
            CtxField::MsgSrcIp4 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.msg_src_ip4 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::MsgSrcIp4 if !self.cgroup_sock_addr_is_ipv4() => Some(
                "ctx.msg_src_ip4 is only available on IPv4 cgroup_sock_addr hooks (*4)".to_string(),
            ),
            CtxField::MsgSrcIp4 if !self.cgroup_sock_addr_has_msg_source() => Some(
                "ctx.msg_src_ip4 is only available on cgroup_sock_addr sendmsg*/recvmsg* hooks"
                    .to_string(),
            ),
            CtxField::MsgSrcIp6 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.msg_src_ip6 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::MsgSrcIp6 if !self.cgroup_sock_addr_is_ipv6() => Some(
                "ctx.msg_src_ip6 is only available on IPv6 cgroup_sock_addr hooks (*6)".to_string(),
            ),
            CtxField::MsgSrcIp6 if !self.cgroup_sock_addr_has_msg_source() => Some(
                "ctx.msg_src_ip6 is only available on cgroup_sock_addr sendmsg*/recvmsg* hooks"
                    .to_string(),
            ),
            CtxField::SockoptRetval if !self.cgroup_sockopt_is_get() => {
                Some("ctx.sockopt_retval is only available on cgroup_sockopt:get hooks".to_string())
            }
            _ => None,
        }
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
            CtxField::Arg(idx)
                if matches!(self.probe_type.arg_access(), ProgramValueAccess::PtRegs) =>
            {
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
                if matches!(
                    self.probe_type.arg_access(),
                    ProgramValueAccess::RawTracepoint
                ) =>
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
            CtxField::Arg(idx) if self.probe_type.uses_btf_trampoline() => {
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
            CtxField::RetVal
                if matches!(self.probe_type.retval_access(), ProgramValueAccess::PtRegs) =>
            {
                KernelBtf::get().pt_regs_offsets().map_err(|e| {
                    CompileError::UnsupportedInstruction(format!(
                        "pt_regs return value access unavailable: {e}"
                    ))
                })?;
            }
            CtxField::RetVal
                if matches!(
                    self.probe_type.retval_access(),
                    ProgramValueAccess::Trampoline
                ) =>
            {
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
                let (category, tp_name) = self.tracepoint_parts().ok_or_else(|| {
                    CompileError::TracepointContextError {
                        category: "unknown".into(),
                        name: self.target.clone(),
                        reason: "Invalid tracepoint format. Expected 'category/name'".into(),
                    }
                })?;
                let ctx = KernelBtf::get()
                    .get_tracepoint_context(&category, &tp_name)
                    .map_err(|e| CompileError::TracepointContextError {
                        category: category.clone(),
                        name: tp_name.clone(),
                        reason: e.to_string(),
                    })?;
                if !ctx.has_field(name) {
                    return Err(CompileError::TracepointFieldNotFound {
                        field: name.clone(),
                        available: ctx.field_names().join(", "),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns a user-facing error message when a helper is not valid
    /// for this program type or attach context.
    pub fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        if let Some(message) = self.probe_type.helper_call_error(helper) {
            return Some(message);
        }
        match helper {
            BpfHelper::Bind
                if self.probe_type == EbpfProgramType::CgroupSockAddr
                    && !self.cgroup_sock_addr_is_connect() =>
            {
                Some(format!(
                    "helper '{}' is only valid on cgroup_sock_addr connect4/connect6 hooks",
                    helper.name()
                ))
            }
            BpfHelper::RedirectPeer if !self.tc_is_ingress() => Some(format!(
                "helper '{}' is only valid in tc ingress programs",
                helper.name()
            )),
            _ => None,
        }
    }

    pub(crate) fn helper_zero_arg_requirement(
        &self,
        helper: BpfHelper,
    ) -> Option<(usize, &'static str)> {
        self.probe_type.helper_zero_arg_requirement(helper)
    }

    fn sched_ext_callback(&self) -> Option<&str> {
        if self.probe_type != EbpfProgramType::StructOps {
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
        let requires_post_bind = matches!(
            member_name,
            "src_ip4" | "src_ip6" | "src_port" | "dst_port" | "dst_ip4" | "dst_ip6"
        );
        if self.probe_type != EbpfProgramType::CgroupSock || !requires_post_bind {
            return None;
        }
        if self.cgroup_sock_is_post_bind() {
            return None;
        }
        Some(format!(
            "ctx.sk.{member_name} is only available on cgroup_sock post_bind4/post_bind6 hooks"
        ))
    }
}
