use super::{
    CompileError, CtxField, EbpfProgramType, IngressIfindexContextLayout, ProbeContext,
    ProgramTargetKind, ProgramValueAccess, SocketContextLayout,
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
use aya::programs::{CgroupSockAddrAttachType, CgroupSockoptAttachType};

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
        self.cgroup_sock_addr_target().is_some_and(|target| {
            matches!(
                target.attach_type,
                CgroupSockAddrAttachType::Bind4
                    | CgroupSockAddrAttachType::Connect4
                    | CgroupSockAddrAttachType::GetPeerName4
                    | CgroupSockAddrAttachType::GetSockName4
                    | CgroupSockAddrAttachType::UDPSendMsg4
                    | CgroupSockAddrAttachType::UDPRecvMsg4
            )
        })
    }

    fn cgroup_sock_addr_is_ipv6(&self) -> bool {
        self.cgroup_sock_addr_target().is_some_and(|target| {
            matches!(
                target.attach_type,
                CgroupSockAddrAttachType::Bind6
                    | CgroupSockAddrAttachType::Connect6
                    | CgroupSockAddrAttachType::GetPeerName6
                    | CgroupSockAddrAttachType::GetSockName6
                    | CgroupSockAddrAttachType::UDPSendMsg6
                    | CgroupSockAddrAttachType::UDPRecvMsg6
            )
        })
    }

    fn cgroup_sock_addr_has_msg_source(&self) -> bool {
        self.cgroup_sock_addr_target().is_some_and(|target| {
            matches!(
                target.attach_type,
                CgroupSockAddrAttachType::UDPSendMsg4
                    | CgroupSockAddrAttachType::UDPSendMsg6
                    | CgroupSockAddrAttachType::UDPRecvMsg4
                    | CgroupSockAddrAttachType::UDPRecvMsg6
            )
        })
    }

    fn cgroup_sockopt_target(&self) -> Option<CgroupSockoptTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::CgroupSockopt { target } => Some(target),
            _ => None,
        }
    }

    fn cgroup_sockopt_is_get(&self) -> bool {
        self.cgroup_sockopt_target()
            .is_some_and(|target| matches!(target.attach_type, CgroupSockoptAttachType::Get))
    }

    pub(crate) fn socket_family_context_layout(&self) -> Option<SocketContextLayout> {
        match self.probe_type {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::CgroupSockAddr => Some(SocketContextLayout::SockAddr),
            EbpfProgramType::SkLookup => Some(SocketContextLayout::SkLookup),
            EbpfProgramType::SkMsg => Some(SocketContextLayout::SkMsg),
            EbpfProgramType::SkSkb | EbpfProgramType::SkSkbParser => {
                Some(SocketContextLayout::SkBuff)
            }
            EbpfProgramType::SockOps => Some(SocketContextLayout::SockOps),
            _ => None,
        }
    }

    pub(crate) fn socket_tuple_context_layout(&self) -> Option<SocketContextLayout> {
        match self.probe_type {
            EbpfProgramType::SkLookup => Some(SocketContextLayout::SkLookup),
            EbpfProgramType::SkMsg => Some(SocketContextLayout::SkMsg),
            EbpfProgramType::SkSkb | EbpfProgramType::SkSkbParser => {
                Some(SocketContextLayout::SkBuff)
            }
            EbpfProgramType::SockOps => Some(SocketContextLayout::SockOps),
            _ => None,
        }
    }

    pub(crate) fn sock_type_context_layout(&self) -> Option<SocketContextLayout> {
        match self.probe_type {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::CgroupSockAddr => Some(SocketContextLayout::SockAddr),
            _ => None,
        }
    }

    pub(crate) fn protocol_context_layout(&self) -> Option<SocketContextLayout> {
        match self.probe_type {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::CgroupSockAddr => Some(SocketContextLayout::SockAddr),
            EbpfProgramType::SkLookup => Some(SocketContextLayout::SkLookup),
            _ => None,
        }
    }

    pub(crate) fn socket_ref_context_layout(&self) -> Option<SocketContextLayout> {
        match self.probe_type {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::CgroupSockopt => Some(SocketContextLayout::CgroupSockopt),
            EbpfProgramType::SkLookup => Some(SocketContextLayout::SkLookup),
            EbpfProgramType::SkMsg => Some(SocketContextLayout::SkMsg),
            _ => None,
        }
    }

    pub(crate) fn ingress_ifindex_context_layout(&self) -> Option<IngressIfindexContextLayout> {
        match self.probe_type {
            EbpfProgramType::Xdp => Some(IngressIfindexContextLayout::XdpMd),
            EbpfProgramType::SocketFilter
            | EbpfProgramType::Tc
            | EbpfProgramType::CgroupSkb
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkSkbParser => Some(IngressIfindexContextLayout::SkBuff),
            EbpfProgramType::SkLookup => Some(IngressIfindexContextLayout::SkLookup),
            _ => None,
        }
    }

    pub(crate) fn sock_mark_priority_context_layout(&self) -> Option<SocketContextLayout> {
        match self.probe_type {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::SocketFilter
            | EbpfProgramType::Tc
            | EbpfProgramType::CgroupSkb
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkSkbParser => Some(SocketContextLayout::SkBuff),
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
        if matches!(self.probe_type, EbpfProgramType::Tracepoint) {
            let resolved = self.probe_type.resolve_ctx_field_name(field_name)?;
            return Ok(match resolved {
                CtxField::Pid
                | CtxField::Tid
                | CtxField::Uid
                | CtxField::Gid
                | CtxField::Comm
                | CtxField::Cpu
                | CtxField::Timestamp
                | CtxField::CgroupId
                | CtxField::KStack
                | CtxField::UStack
                | CtxField::Arg(_) => resolved,
                _ => CtxField::TracepointField(field_name.to_string()),
            });
        }

        self.probe_type.resolve_ctx_field_name(field_name)
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
        path_desc: &str,
    ) -> Result<CtxStoreTarget, String> {
        match (self.probe_type, field_name, index) {
            (EbpfProgramType::SockOps, "reply", None) => Ok(CtxStoreTarget::SockOpsReply),
            (EbpfProgramType::SockOps, "replylong", Some(index)) => {
                let index = u8::try_from(index)
                    .map_err(|_| format!("ctx.replylong index must be in 0..=3, got {}", index))?;
                if index >= 4 {
                    return Err(format!(
                        "ctx.replylong index must be in 0..=3, got {}",
                        index
                    ));
                }
                Ok(CtxStoreTarget::SockOpsReplyLong(index))
            }
            (EbpfProgramType::SockOps, "replylong", None) => Err(
                "ctx.replylong assignment requires a fixed index, e.g. $ctx.replylong.0 = ..."
                    .into(),
            ),
            (EbpfProgramType::CgroupSockopt, "sockopt_retval", None) => {
                self.validate_ctx_field_access(&CtxField::SockoptRetval)
                    .map_err(|err| err.to_string())?;
                Ok(CtxStoreTarget::SockoptRetval)
            }
            _ => Err(format!(
                "context cell path update '.{} = ...' is only supported for sock_ops reply fields and cgroup_sockopt:get sockopt_retval",
                path_desc
            )),
        }
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
            CtxStoreTarget::SockoptRetval => self.ctx_field_access_error(&CtxField::SockoptRetval),
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
        let packet_field_error = |field: &CtxField| {
            if self.probe_type.packet_context_kind().is_some() {
                format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    self.probe_type.canonical_prefix()
                )
            } else {
                format!(
                    "ctx.{} is only available on packet-context programs (xdp, socket_filter, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, and packet-aware sock_ops callbacks)",
                    field.display_name()
                )
            }
        };
        let program_type = self.probe_type;

        match field {
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid | CtxField::Comm
                if !program_type.supports_task_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    program_type.canonical_prefix()
                ))
            }
            CtxField::Cpu if !program_type.supports_cpu_ctx_field() => Some(format!(
                "ctx.{} is not available on {} programs",
                field.display_name(),
                program_type.canonical_prefix()
            )),
            CtxField::Timestamp if !program_type.supports_timestamp_ctx_field() => Some(
                format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    program_type.canonical_prefix()
                ),
            ),
            CtxField::PacketLen if !program_type.supports_packet_len_ctx_field() => {
                Some(packet_field_error(field))
            }
            CtxField::PktType
            | CtxField::QueueMapping
            | CtxField::EthProtocol
            | CtxField::VlanPresent
            | CtxField::VlanTci
            | CtxField::VlanProto
            | CtxField::SkbCb
            | CtxField::TcClassid
            | CtxField::NapiId
            | CtxField::WireLen
            | CtxField::GsoSegs
            | CtxField::GsoSize
            | CtxField::Hwtstamp
                if !program_type.supports_skb_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::Data | CtxField::DataEnd if !program_type.supports_packet_data_ctx_fields() =>
            {
                Some(packet_field_error(field))
            }
            CtxField::IngressIfindex if !program_type.supports_ingress_ifindex_ctx_field() => {
                Some(packet_field_error(field))
            }
            CtxField::Ifindex if !program_type.supports_skb_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::TcIndex | CtxField::SkbHash if !program_type.supports_skb_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::RxQueueIndex if !program_type.supports_rx_queue_index_ctx_field() => {
                Some(packet_field_error(field))
            }
            CtxField::EgressIfindex if !program_type.supports_egress_ifindex_ctx_field() => {
                Some(packet_field_error(field))
            }
            CtxField::RemoteIp4
            | CtxField::RemoteIp6
            | CtxField::RemotePort
            | CtxField::LocalIp4
            | CtxField::LocalIp6
            | CtxField::LocalPort
                if !program_type.supports_socket_tuple_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::Socket if !program_type.supports_socket_ref_ctx_field() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sockopt, sk_lookup, and sk_msg programs",
                    field.display_name()
                ))
            }
            CtxField::LookupCookie if !program_type.supports_lookup_cookie_ctx_field() => {
                Some(format!(
                    "ctx.{} is only available on sk_lookup programs",
                    field.display_name()
                ))
            }
            CtxField::SocketCookie if !program_type.supports_socket_cookie_ctx_field() =>
            {
                Some(format!(
                    "ctx.{} is only available on skb-backed packet programs, cgroup_sock, cgroup_sock_addr, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::SocketUid if !program_type.supports_socket_uid_ctx_field() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, and sk_skb programs",
                    field.display_name()
                ))
            }
            CtxField::NetnsCookie if !program_type.supports_netns_cookie_ctx_field() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::DeviceAccessType | CtxField::DeviceMajor | CtxField::DeviceMinor
                if !program_type.supports_device_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_device programs",
                    field.display_name()
                ))
            }
            CtxField::SockOp
            | CtxField::SockOpsArgs
            | CtxField::IsFullsock
            | CtxField::SockOpsSndCwnd
            | CtxField::SockOpsSrttUs
            | CtxField::SockOpsCbFlags
            | CtxField::SockState
            | CtxField::SockOpsRttMin
            | CtxField::SockOpsSndSsthresh
            | CtxField::SockOpsRcvNxt
            | CtxField::SockOpsSndNxt
            | CtxField::SockOpsSndUna
            | CtxField::SockOpsMssCache
            | CtxField::SockOpsEcnFlags
            | CtxField::SockOpsRateDelivered
            | CtxField::SockOpsRateIntervalUs
            | CtxField::SockOpsPacketsOut
            | CtxField::SockOpsRetransOut
            | CtxField::SockOpsTotalRetrans
            | CtxField::SockOpsSegsIn
            | CtxField::SockOpsDataSegsIn
            | CtxField::SockOpsSegsOut
            | CtxField::SockOpsDataSegsOut
            | CtxField::SockOpsLostOut
            | CtxField::SockOpsSackedOut
            | CtxField::SockOpsSkTxhash
            | CtxField::SockOpsBytesReceived
            | CtxField::SockOpsBytesAcked
            | CtxField::SockOpsSkbLen
            | CtxField::SockOpsSkbTcpFlags
            | CtxField::SockOpsSkbHwtstamp
                if !program_type.supports_sock_ops_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::UserFamily | CtxField::UserPort
                if !program_type.supports_cgroup_sock_addr_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock_addr programs",
                    field.display_name()
                ))
            }
            CtxField::Family if !program_type.supports_socket_common_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::SockType | CtxField::Protocol
                if !program_type.supports_sock_type_protocol_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, and sk_lookup programs",
                    field.display_name()
                ))
            }
            CtxField::BoundDevIf if !program_type.supports_cgroup_sock_ctx_fields() => {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock programs",
                    field.display_name()
                ))
            }
            CtxField::SockMark | CtxField::SockPriority
                if !program_type.supports_sock_mark_priority_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
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
                "ctx.msg_src_ip4 is only available on IPv4 cgroup_sock_addr hooks (*4)"
                    .to_string(),
            ),
            CtxField::MsgSrcIp4 if !self.cgroup_sock_addr_has_msg_source() => Some(
                "ctx.msg_src_ip4 is only available on cgroup_sock_addr sendmsg*/recvmsg* hooks"
                    .to_string(),
            ),
            CtxField::MsgSrcIp6 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.msg_src_ip6 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::MsgSrcIp6 if !self.cgroup_sock_addr_is_ipv6() => Some(
                "ctx.msg_src_ip6 is only available on IPv6 cgroup_sock_addr hooks (*6)"
                    .to_string(),
            ),
            CtxField::MsgSrcIp6 if !self.cgroup_sock_addr_has_msg_source() => Some(
                "ctx.msg_src_ip6 is only available on cgroup_sock_addr sendmsg*/recvmsg* hooks"
                    .to_string(),
            ),
            CtxField::SysctlWrite | CtxField::SysctlFilePos
                if !program_type.supports_cgroup_sysctl_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sysctl programs",
                    field.display_name()
                ))
            }
            CtxField::SockoptLevel
            | CtxField::SockoptOptname
            | CtxField::SockoptOptlen
            | CtxField::SockoptOptval
            | CtxField::SockoptOptvalEnd
                if !program_type.supports_cgroup_sockopt_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sockopt programs",
                    field.display_name()
                ))
            }
            CtxField::SockoptRetval if !program_type.supports_cgroup_sockopt_ctx_fields() => {
                Some("ctx.sockopt_retval is only available on cgroup_sockopt programs".to_string())
            }
            CtxField::SockoptRetval if !self.cgroup_sockopt_is_get() => Some(
                "ctx.sockopt_retval is only available on cgroup_sockopt:get hooks".to_string(),
            ),
            CtxField::LircSample | CtxField::LircValue | CtxField::LircMode
                if !program_type.supports_lirc_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on lirc_mode2 programs",
                    field.display_name()
                ))
            }
            CtxField::Arg(_) if !program_type.supports_ctx_args() => Some(format!(
                "ctx.{} is only available on contexts with argument access (kprobe, uprobe, fentry, fexit, tp_btf, lsm, struct_ops, and raw_tracepoint)",
                field.display_name()
            )),
            CtxField::RetVal if !program_type.supports_ctx_retval() => Some(
                "ctx.retval is only available on return probes with return-value access (kretprobe, uretprobe, fexit)".to_string(),
            ),
            CtxField::KStack | CtxField::UStack if !program_type.supports_stack_ctx_fields() => {
                Some(format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    program_type.canonical_prefix()
                ))
            }
            CtxField::TracepointField(name) if !program_type.supports_tracepoint_fields() => {
                Some(format!(
                    "ctx.{} is only available on typed tracepoints (`tracepoint:category/name`)",
                    name
                ))
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
