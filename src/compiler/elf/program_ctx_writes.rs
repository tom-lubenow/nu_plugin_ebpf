use super::{CtxWriteTarget, EbpfProgramType, ProgramContextFamily};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::{CtxField, CtxStoreTarget};
use crate::program_spec::{ProgramAttachAddressFamily, ProgramAttachShape, ProgramSpec};

fn bounded_index(field_name: &str, index: usize, upper_inclusive: u8) -> Result<u8, String> {
    let index = u8::try_from(index).map_err(|_| {
        format!("ctx.{field_name} index must be in 0..={upper_inclusive}, got {index}")
    })?;
    if index > upper_inclusive {
        return Err(format!(
            "ctx.{field_name} index must be in 0..={upper_inclusive}, got {index}"
        ));
    }
    Ok(index)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextStoreTargetSpec {
    Fixed(CtxStoreTarget),
    SockOpsReplyLongWord,
    SkbCbWord,
    CgroupSockAddrUserIp6Word,
    CgroupSockAddrMsgSrcIp6Word,
    CgroupSockAddrLocalIp4Alias,
    CgroupSockAddrLocalIp6WordAlias,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextWriteTargetSpec {
    Store(ContextStoreTargetSpec),
    SysctlNewValue,
    SockoptOptvalByte,
    AssignSocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextWriteAvailability {
    CgroupSockCreateReleaseOnly,
    CgroupSockoptSetOnly,
    CgroupSkbEgressOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContextWriteSurfaceSpec {
    field_name: &'static str,
    field: Option<CtxField>,
    target: ContextWriteTargetSpec,
    availability: Option<ContextWriteAvailability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProgramContextWriteSurfaceSpec {
    program_type: EbpfProgramType,
    surfaces: &'static [ContextWriteSurfaceSpec],
}

impl ContextStoreTargetSpec {
    fn resolve(
        &self,
        spec: &ProgramSpec,
        field_name: &str,
        index: Option<usize>,
    ) -> Result<CtxStoreTarget, String> {
        match self {
            Self::Fixed(target) => match index {
                Some(_) => Err(format!(
                    "ctx.{field_name} does not support indexed assignment"
                )),
                None => Ok(target.clone()),
            },
            Self::SockOpsReplyLongWord => match index {
                Some(index) => {
                    bounded_index(field_name, index, 3).map(CtxStoreTarget::SockOpsReplyLong)
                }
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
            Self::SkbCbWord => match index {
                Some(index) => bounded_index(field_name, index, 4).map(CtxStoreTarget::SkbCbWord),
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
            Self::CgroupSockAddrUserIp6Word => match index {
                Some(index) => bounded_index(field_name, index, 3)
                    .map(CtxStoreTarget::CgroupSockAddrUserIp6Word),
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
            Self::CgroupSockAddrMsgSrcIp6Word => match index {
                Some(index) => bounded_index(field_name, index, 3)
                    .map(CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word),
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
            Self::CgroupSockAddrLocalIp4Alias => match index {
                Some(_) => Err(format!(
                    "ctx.{field_name} does not support indexed assignment"
                )),
                None => spec
                    .attach_shape()
                    .cgroup_sock_addr()
                    .and_then(|(family, hook)| {
                        (family == ProgramAttachAddressFamily::Ipv4).then_some(hook)
                    })
                    .and_then(|hook| {
                        if hook.is_sendmsg() {
                            Some(CtxStoreTarget::CgroupSockAddrMsgSrcIp4)
                        } else if hook.exposes_local_tuple() {
                            Some(CtxStoreTarget::CgroupSockAddrUserIp4)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| format!("ctx.{field_name} is not available on this hook")),
            },
            Self::CgroupSockAddrLocalIp6WordAlias => match index {
                Some(index) => {
                    let index = bounded_index(field_name, index, 3)?;
                    spec.attach_shape()
                        .cgroup_sock_addr()
                        .and_then(|(family, hook)| {
                            (family == ProgramAttachAddressFamily::Ipv6).then_some(hook)
                        })
                        .and_then(|hook| {
                            if hook.is_sendmsg() {
                                Some(CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(index))
                            } else if hook.exposes_local_tuple() {
                                Some(CtxStoreTarget::CgroupSockAddrUserIp6Word(index))
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| format!("ctx.{field_name} is not available on this hook"))
                }
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
        }
    }

    fn matches_target(&self, target: &CtxStoreTarget) -> bool {
        match (self, target) {
            (Self::Fixed(expected), actual) => expected == actual,
            (Self::SockOpsReplyLongWord, CtxStoreTarget::SockOpsReplyLong(_)) => true,
            (Self::SkbCbWord, CtxStoreTarget::SkbCbWord(_)) => true,
            (Self::CgroupSockAddrUserIp6Word, CtxStoreTarget::CgroupSockAddrUserIp6Word(_)) => true,
            (Self::CgroupSockAddrMsgSrcIp6Word, CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_)) => {
                true
            }
            (Self::CgroupSockAddrLocalIp4Alias, _) => false,
            (Self::CgroupSockAddrLocalIp6WordAlias, _) => false,
            _ => false,
        }
    }
}

impl ContextWriteTargetSpec {
    fn resolve(
        &self,
        spec: &ProgramSpec,
        field_name: &str,
        index: Option<usize>,
    ) -> Result<CtxWriteTarget, String> {
        match self {
            Self::Store(target) => target
                .resolve(spec, field_name, index)
                .map(CtxWriteTarget::StoreField),
            Self::SysctlNewValue => match index {
                Some(_) => Err(format!(
                    "ctx.{field_name} does not support indexed assignment"
                )),
                None => Ok(CtxWriteTarget::SysctlNewValue),
            },
            Self::SockoptOptvalByte => match index {
                Some(index) => Ok(CtxWriteTarget::SockoptOptvalByte(index)),
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
            Self::AssignSocket => match index {
                Some(_) => Err(format!(
                    "ctx.{field_name} does not support indexed assignment"
                )),
                None => spec
                    .helper_call_error(BpfHelper::SkAssign)
                    .map_or(Ok(CtxWriteTarget::AssignSocket), Err),
            },
        }
    }

    fn matches_store_target(&self, target: &CtxStoreTarget) -> bool {
        match self {
            Self::Store(spec) => spec.matches_target(target),
            Self::SysctlNewValue => false,
            Self::SockoptOptvalByte => false,
            Self::AssignSocket => false,
        }
    }
}

impl ContextWriteAvailability {
    fn error(&self, spec: &ProgramSpec, field_name: &str) -> Option<String> {
        let attach_shape = spec.attach_shape();
        match self {
            Self::CgroupSockCreateReleaseOnly => {
                attach_shape.is_cgroup_sock_post_bind().then(|| {
                    format!(
                    "ctx.{field_name} is only writable on cgroup_sock sock_create/sock_release hooks"
                )
                })
            }
            Self::CgroupSockoptSetOnly => attach_shape.is_cgroup_sockopt_get().then(|| {
                format!("ctx.{field_name} is only writable on cgroup_sockopt:set hooks")
            }),
            Self::CgroupSkbEgressOnly => attach_shape.is_cgroup_skb_ingress().then(|| {
                format!(
                    "ctx.{field_name} is only writable on tc and cgroup_skb:egress programs"
                )
            }),
        }
    }
}

impl ContextWriteSurfaceSpec {
    const fn store_field(
        field_name: &'static str,
        field: CtxField,
        target: ContextStoreTargetSpec,
    ) -> Self {
        Self {
            field_name,
            field: Some(field),
            target: ContextWriteTargetSpec::Store(target),
            availability: None,
        }
    }

    const fn named_store(field_name: &'static str, target: ContextStoreTargetSpec) -> Self {
        Self {
            field_name,
            field: None,
            target: ContextWriteTargetSpec::Store(target),
            availability: None,
        }
    }

    const fn special_write(field_name: &'static str, target: ContextWriteTargetSpec) -> Self {
        Self {
            field_name,
            field: None,
            target,
            availability: None,
        }
    }

    const fn with_availability(mut self, availability: ContextWriteAvailability) -> Self {
        self.availability = Some(availability);
        self
    }

    fn matches_field_name(&self, field_name: &str) -> bool {
        self.field_name == field_name
    }

    fn matches_store_target(&self, target: &CtxStoreTarget) -> bool {
        self.target.matches_store_target(target)
    }

    fn resolve_write_target(
        &self,
        spec: &ProgramSpec,
        index: Option<usize>,
    ) -> Result<CtxWriteTarget, String> {
        if let Some(field) = self.field.as_ref() {
            if let Some(err) = spec.ctx_field_access_error(field) {
                return Err(err);
            }
        }

        let write_target = self.target.resolve(spec, self.field_name, index)?;
        if let Some(err) = self
            .availability
            .and_then(|availability| availability.error(spec, self.field_name))
        {
            return Err(err);
        }

        Ok(write_target)
    }

    fn resolve_store_target(
        &self,
        spec: &ProgramSpec,
        index: Option<usize>,
    ) -> Option<Result<CtxStoreTarget, String>> {
        match self.target {
            ContextWriteTargetSpec::Store(_) => Some(self.resolve_write_target(spec, index).map(
                |target| match target {
                    CtxWriteTarget::StoreField(target) => target,
                    CtxWriteTarget::SysctlNewValue => unreachable!(),
                    CtxWriteTarget::SockoptOptvalByte(_) => unreachable!(),
                    CtxWriteTarget::AssignSocket => unreachable!(),
                },
            )),
            ContextWriteTargetSpec::SysctlNewValue => None,
            ContextWriteTargetSpec::SockoptOptvalByte => None,
            ContextWriteTargetSpec::AssignSocket => None,
        }
    }

    fn store_target_error(&self, spec: &ProgramSpec) -> Option<String> {
        self.field
            .as_ref()
            .and_then(|field| spec.ctx_field_access_error(field))
            .or_else(|| {
                self.availability
                    .and_then(|availability| availability.error(spec, self.field_name))
            })
    }
}

const SOCKET_FILTER_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] =
    &[ContextWriteSurfaceSpec::store_field(
        "cb",
        CtxField::SkbCb,
        ContextStoreTargetSpec::SkbCbWord,
    )];

const TC_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::special_write("sk", ContextWriteTargetSpec::AssignSocket),
    ContextWriteSurfaceSpec::store_field(
        "mark",
        CtxField::SockMark,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbMark),
    ),
    ContextWriteSurfaceSpec::store_field(
        "priority",
        CtxField::SockPriority,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbPriority),
    ),
    ContextWriteSurfaceSpec::store_field(
        "tc_index",
        CtxField::TcIndex,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbTcIndex),
    ),
    ContextWriteSurfaceSpec::store_field("cb", CtxField::SkbCb, ContextStoreTargetSpec::SkbCbWord),
    ContextWriteSurfaceSpec::store_field(
        "tc_classid",
        CtxField::TcClassid,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbTcClassid),
    ),
    ContextWriteSurfaceSpec::store_field(
        "tstamp",
        CtxField::Tstamp,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbTstamp),
    ),
];

const SK_SKB_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::store_field(
        "priority",
        CtxField::SockPriority,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbPriority),
    ),
    ContextWriteSurfaceSpec::store_field(
        "tc_index",
        CtxField::TcIndex,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbTcIndex),
    ),
];

const CGROUP_SKB_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::store_field(
        "mark",
        CtxField::SockMark,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbMark),
    ),
    ContextWriteSurfaceSpec::store_field(
        "priority",
        CtxField::SockPriority,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbPriority),
    ),
    ContextWriteSurfaceSpec::store_field("cb", CtxField::SkbCb, ContextStoreTargetSpec::SkbCbWord),
    ContextWriteSurfaceSpec::store_field(
        "tstamp",
        CtxField::Tstamp,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbTstamp),
    )
    .with_availability(ContextWriteAvailability::CgroupSkbEgressOnly),
];

const CGROUP_SOCK_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::named_store(
        "bound_dev_if",
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockBoundDevIf),
    )
    .with_availability(ContextWriteAvailability::CgroupSockCreateReleaseOnly),
    ContextWriteSurfaceSpec::named_store(
        "mark",
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockMark),
    )
    .with_availability(ContextWriteAvailability::CgroupSockCreateReleaseOnly),
    ContextWriteSurfaceSpec::named_store(
        "priority",
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockPriority),
    )
    .with_availability(ContextWriteAvailability::CgroupSockCreateReleaseOnly),
];

const CGROUP_SYSCTL_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::store_field(
        "file_pos",
        CtxField::SysctlFilePos,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SysctlFilePos),
    ),
    ContextWriteSurfaceSpec::special_write(
        "sysctl_new_value",
        ContextWriteTargetSpec::SysctlNewValue,
    ),
    ContextWriteSurfaceSpec::special_write("new_value", ContextWriteTargetSpec::SysctlNewValue),
];

const SOCK_OPS_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::named_store(
        "reply",
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockOpsReply),
    ),
    ContextWriteSurfaceSpec::named_store("replylong", ContextStoreTargetSpec::SockOpsReplyLongWord),
    ContextWriteSurfaceSpec::store_field(
        "cb_flags",
        CtxField::SockOpsCbFlags,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockOpsCbFlags),
    ),
    ContextWriteSurfaceSpec::store_field(
        "sk_txhash",
        CtxField::SockOpsSkTxhash,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockOpsSkTxhash),
    ),
];

const CGROUP_SOCKOPT_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::store_field(
        "level",
        CtxField::SockoptLevel,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockoptLevel),
    )
    .with_availability(ContextWriteAvailability::CgroupSockoptSetOnly),
    ContextWriteSurfaceSpec::store_field(
        "optname",
        CtxField::SockoptOptname,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockoptOptname),
    )
    .with_availability(ContextWriteAvailability::CgroupSockoptSetOnly),
    ContextWriteSurfaceSpec::store_field(
        "optlen",
        CtxField::SockoptOptlen,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockoptOptlen),
    ),
    ContextWriteSurfaceSpec::store_field(
        "sockopt_retval",
        CtxField::SockoptRetval,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockoptRetval),
    ),
    ContextWriteSurfaceSpec::store_field(
        "retval",
        CtxField::SockoptRetval,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockoptRetval),
    ),
    ContextWriteSurfaceSpec::special_write("optval", ContextWriteTargetSpec::SockoptOptvalByte),
];

const CGROUP_SOCK_ADDR_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::store_field(
        "user_ip4",
        CtxField::UserIp4,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockAddrUserIp4),
    ),
    ContextWriteSurfaceSpec::store_field(
        "user_ip6",
        CtxField::UserIp6,
        ContextStoreTargetSpec::CgroupSockAddrUserIp6Word,
    ),
    ContextWriteSurfaceSpec::store_field(
        "user_port",
        CtxField::UserPort,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockAddrUserPort),
    ),
    ContextWriteSurfaceSpec::store_field(
        "msg_src_ip4",
        CtxField::MsgSrcIp4,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockAddrMsgSrcIp4),
    ),
    ContextWriteSurfaceSpec::store_field(
        "msg_src_ip6",
        CtxField::MsgSrcIp6,
        ContextStoreTargetSpec::CgroupSockAddrMsgSrcIp6Word,
    ),
    ContextWriteSurfaceSpec::store_field(
        "remote_ip4",
        CtxField::RemoteIp4,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockAddrUserIp4),
    ),
    ContextWriteSurfaceSpec::store_field(
        "remote_ip6",
        CtxField::RemoteIp6,
        ContextStoreTargetSpec::CgroupSockAddrUserIp6Word,
    ),
    ContextWriteSurfaceSpec::store_field(
        "remote_port",
        CtxField::RemotePort,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockAddrUserPort),
    ),
    ContextWriteSurfaceSpec::store_field(
        "local_ip4",
        CtxField::LocalIp4,
        ContextStoreTargetSpec::CgroupSockAddrLocalIp4Alias,
    ),
    ContextWriteSurfaceSpec::store_field(
        "local_ip6",
        CtxField::LocalIp6,
        ContextStoreTargetSpec::CgroupSockAddrLocalIp6WordAlias,
    ),
    ContextWriteSurfaceSpec::store_field(
        "local_port",
        CtxField::LocalPort,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockAddrUserPort),
    ),
];

const SK_LOOKUP_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] =
    &[ContextWriteSurfaceSpec::special_write(
        "sk",
        ContextWriteTargetSpec::AssignSocket,
    )];

const PROGRAM_CTX_WRITE_SURFACES: &[ProgramContextWriteSurfaceSpec] = &[
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::SocketFilter,
        surfaces: SOCKET_FILTER_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::Tc,
        surfaces: TC_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::SkSkb,
        surfaces: SK_SKB_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::SkSkbParser,
        surfaces: SK_SKB_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::CgroupSkb,
        surfaces: CGROUP_SKB_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::CgroupSysctl,
        surfaces: CGROUP_SYSCTL_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::SockOps,
        surfaces: SOCK_OPS_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::SkLookup,
        surfaces: SK_LOOKUP_CTX_WRITE_SURFACES,
    },
];

fn find_ctx_write_surface(
    field_name: &str,
    surfaces: &[ContextWriteSurfaceSpec],
) -> Option<ContextWriteSurfaceSpec> {
    surfaces
        .iter()
        .find(|surface| surface.matches_field_name(field_name))
        .cloned()
}

fn find_ctx_store_surface(
    target: &CtxStoreTarget,
    surfaces: &[ContextWriteSurfaceSpec],
) -> Option<ContextWriteSurfaceSpec> {
    surfaces
        .iter()
        .find(|surface| surface.matches_store_target(target))
        .cloned()
}

fn program_ctx_write_surfaces(
    program_type: EbpfProgramType,
) -> Option<&'static [ContextWriteSurfaceSpec]> {
    PROGRAM_CTX_WRITE_SURFACES
        .iter()
        .find(|surface| surface.program_type == program_type)
        .map(|surface| surface.surfaces)
}

impl CtxStoreTarget {
    pub(crate) fn ctx_field(&self) -> Option<CtxField> {
        match self {
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => None,
            CtxStoreTarget::SockOpsCbFlags => Some(CtxField::SockOpsCbFlags),
            CtxStoreTarget::SockOpsSkTxhash => Some(CtxField::SockOpsSkTxhash),
            CtxStoreTarget::CgroupSockBoundDevIf
            | CtxStoreTarget::CgroupSockMark
            | CtxStoreTarget::CgroupSockPriority => None,
            CtxStoreTarget::SkbMark => Some(CtxField::SockMark),
            CtxStoreTarget::SkbPriority => Some(CtxField::SockPriority),
            CtxStoreTarget::SkbTcIndex => Some(CtxField::TcIndex),
            CtxStoreTarget::SkbCbWord(_) => Some(CtxField::SkbCb),
            CtxStoreTarget::SkbTcClassid => Some(CtxField::TcClassid),
            CtxStoreTarget::SkbTstamp => Some(CtxField::Tstamp),
            CtxStoreTarget::SysctlFilePos => Some(CtxField::SysctlFilePos),
            CtxStoreTarget::SockoptLevel => Some(CtxField::SockoptLevel),
            CtxStoreTarget::SockoptOptname => Some(CtxField::SockoptOptname),
            CtxStoreTarget::SockoptOptlen => Some(CtxField::SockoptOptlen),
            CtxStoreTarget::SockoptRetval => Some(CtxField::SockoptRetval),
            CtxStoreTarget::CgroupSockAddrUserIp4 => Some(CtxField::UserIp4),
            CtxStoreTarget::CgroupSockAddrUserIp6Word(_) => Some(CtxField::UserIp6),
            CtxStoreTarget::CgroupSockAddrUserPort => Some(CtxField::UserPort),
            CtxStoreTarget::CgroupSockAddrMsgSrcIp4 => Some(CtxField::MsgSrcIp4),
            CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_) => Some(CtxField::MsgSrcIp6),
        }
    }

    fn required_context_family(&self) -> Option<ProgramContextFamily> {
        match self {
            CtxStoreTarget::SockOpsReply
            | CtxStoreTarget::SockOpsReplyLong(_)
            | CtxStoreTarget::SockOpsCbFlags
            | CtxStoreTarget::SockOpsSkTxhash => Some(ProgramContextFamily::SockOps),
            CtxStoreTarget::CgroupSockBoundDevIf
            | CtxStoreTarget::CgroupSockMark
            | CtxStoreTarget::CgroupSockPriority => Some(ProgramContextFamily::CgroupSock),
            _ => None,
        }
    }
}

impl EbpfProgramType {
    pub(crate) fn base_ctx_store_target_error(&self, target: &CtxStoreTarget) -> Option<String> {
        target
            .required_context_family()
            .filter(|required_family| self.context_family() != *required_family)
            .map(|_| target.missing_context_error().to_string())
            .or_else(|| {
                target
                    .ctx_field()
                    .and_then(|field| self.base_ctx_field_access_error(&field))
            })
    }
}

impl ProgramSpec {
    fn ctx_write_surfaces(&self) -> Option<&'static [ContextWriteSurfaceSpec]> {
        match self.attach_shape() {
            ProgramAttachShape::CgroupSock { .. } => Some(CGROUP_SOCK_CTX_WRITE_SURFACES),
            ProgramAttachShape::CgroupSockopt { .. } => Some(CGROUP_SOCKOPT_CTX_WRITE_SURFACES),
            ProgramAttachShape::CgroupSockAddr { .. } => Some(CGROUP_SOCK_ADDR_CTX_WRITE_SURFACES),
            _ => program_ctx_write_surfaces(self.program_type()),
        }
    }

    fn ctx_write_surface_for_name(&self, field_name: &str) -> Option<ContextWriteSurfaceSpec> {
        self.ctx_write_surfaces()
            .and_then(|surfaces| find_ctx_write_surface(field_name, surfaces))
    }

    fn ctx_write_surface_for_store_target(
        &self,
        target: &CtxStoreTarget,
    ) -> Option<ContextWriteSurfaceSpec> {
        self.ctx_write_surfaces()
            .and_then(|surfaces| find_ctx_store_surface(target, surfaces))
    }

    pub(crate) fn resolve_ctx_store_target(
        &self,
        field_name: &str,
        index: Option<usize>,
    ) -> Option<Result<CtxStoreTarget, String>> {
        self.ctx_write_surface_for_name(field_name)
            .and_then(|surface| surface.resolve_store_target(self, index))
    }

    pub(crate) fn resolve_ctx_write_target(
        &self,
        field_name: &str,
        index: Option<usize>,
    ) -> Option<Result<CtxWriteTarget, String>> {
        self.ctx_write_surface_for_name(field_name)
            .map(|surface| surface.resolve_write_target(self, index))
    }

    pub(crate) fn ctx_store_target_error(&self, store_target: &CtxStoreTarget) -> Option<String> {
        if let Some(surface) = self.ctx_write_surface_for_store_target(store_target) {
            return surface.store_target_error(self);
        }

        if let Some(field) = store_target.ctx_field() {
            return self
                .ctx_field_access_error(&field)
                .or_else(|| Some(store_target.missing_context_error().to_string()));
        }

        self.program_type()
            .base_ctx_store_target_error(store_target)
    }
}
