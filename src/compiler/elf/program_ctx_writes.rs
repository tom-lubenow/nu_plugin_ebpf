use super::{
    CtxWriteTarget, EbpfProgramType, ProgramCompatibilityRequirement, ProgramContextFamily,
};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::{ContextFieldCompatibilityRequirement, CtxField, CtxStoreTarget};
use crate::program_spec::{ProgramAttachAddressFamily, ProgramSpec};

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
    CgroupSockAddrSunPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextWriteAvailability {
    CgroupSockCreateReleaseOnly,
    CgroupSockoptSetOnly,
    CgroupSkbEgressOnly,
    CgroupSockAddrUnixOnly,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextWriteSurface {
    pub(crate) field_name: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) indexed: bool,
    pub(crate) minimum_kernel: Option<&'static str>,
    pub(crate) minimum_kernel_source: Option<&'static str>,
    pub(crate) helper: Option<BpfHelper>,
    pub(crate) kfunc: Option<&'static str>,
}

impl ContextStoreTargetSpec {
    fn requires_indexed_assignment(&self) -> bool {
        matches!(
            self,
            Self::SockOpsReplyLongWord
                | Self::SkbCbWord
                | Self::CgroupSockAddrUserIp6Word
                | Self::CgroupSockAddrMsgSrcIp6Word
                | Self::CgroupSockAddrLocalIp6WordAlias
        )
    }

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

    fn backing_helper(&self) -> Option<BpfHelper> {
        match self {
            Self::Fixed(CtxStoreTarget::SockOpsCbFlags) => Some(BpfHelper::SockOpsCbFlagsSet),
            Self::Fixed(_)
            | Self::SockOpsReplyLongWord
            | Self::SkbCbWord
            | Self::CgroupSockAddrUserIp6Word
            | Self::CgroupSockAddrMsgSrcIp6Word
            | Self::CgroupSockAddrLocalIp4Alias
            | Self::CgroupSockAddrLocalIp6WordAlias => None,
        }
    }

    fn compatibility_requirement(&self) -> Option<ProgramCompatibilityRequirement> {
        match self {
            Self::Fixed(CtxStoreTarget::SockOpsReply) | Self::SockOpsReplyLongWord => {
                Some(ProgramCompatibilityRequirement::SockOpsProgram)
            }
            Self::Fixed(_)
            | Self::SkbCbWord
            | Self::CgroupSockAddrUserIp6Word
            | Self::CgroupSockAddrMsgSrcIp6Word
            | Self::CgroupSockAddrLocalIp4Alias
            | Self::CgroupSockAddrLocalIp6WordAlias => None,
        }
    }
}

impl ContextWriteTargetSpec {
    fn kind(&self) -> &'static str {
        match self {
            Self::Store(_) => "store",
            Self::SysctlNewValue => "sysctl-new-value",
            Self::SockoptOptvalByte => "sockopt-optval-byte",
            Self::AssignSocket => "assign-socket",
            Self::CgroupSockAddrSunPath => "sun-path",
        }
    }

    fn requires_indexed_assignment(&self) -> bool {
        match self {
            Self::Store(target) => target.requires_indexed_assignment(),
            Self::SockoptOptvalByte => true,
            Self::SysctlNewValue | Self::AssignSocket | Self::CgroupSockAddrSunPath => false,
        }
    }

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
            Self::CgroupSockAddrSunPath => match index {
                Some(_) => Err(format!(
                    "ctx.{field_name} does not support indexed assignment"
                )),
                None => spec
                    .kfunc_call_error("bpf_sock_addr_set_sun_path")
                    .map_or(Ok(CtxWriteTarget::CgroupSockAddrSunPath), Err),
            },
        }
    }

    fn matches_store_target(&self, target: &CtxStoreTarget) -> bool {
        match self {
            Self::Store(spec) => spec.matches_target(target),
            Self::SysctlNewValue => false,
            Self::SockoptOptvalByte => false,
            Self::AssignSocket => false,
            Self::CgroupSockAddrSunPath => false,
        }
    }

    fn backing_helper(&self) -> Option<BpfHelper> {
        match self {
            Self::Store(spec) => spec.backing_helper(),
            Self::SysctlNewValue => Some(BpfHelper::SysctlSetNewValue),
            Self::AssignSocket => Some(BpfHelper::SkAssign),
            Self::SockoptOptvalByte | Self::CgroupSockAddrSunPath => None,
        }
    }

    fn backing_kfunc(&self) -> Option<&'static str> {
        match self {
            Self::CgroupSockAddrSunPath => Some("bpf_sock_addr_set_sun_path"),
            Self::Store(_)
            | Self::SysctlNewValue
            | Self::SockoptOptvalByte
            | Self::AssignSocket => None,
        }
    }

    fn compatibility_requirement(&self) -> Option<ProgramCompatibilityRequirement> {
        match self {
            Self::Store(target) => target.compatibility_requirement(),
            Self::SysctlNewValue
            | Self::SockoptOptvalByte
            | Self::AssignSocket
            | Self::CgroupSockAddrSunPath => None,
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
                    "ctx.{field_name} is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
                )
            }),
            Self::CgroupSockAddrUnixOnly => attach_shape.cgroup_sock_addr().and_then(
                |(family, _)| {
                    (family != ProgramAttachAddressFamily::Unix).then(|| {
                        format!(
                            "ctx.{field_name} is only writable on cgroup_sock_addr UNIX hooks"
                        )
                    })
                },
            ),
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

    const fn special_write_field(
        field_name: &'static str,
        field: CtxField,
        target: ContextWriteTargetSpec,
    ) -> Self {
        Self {
            field_name,
            field: Some(field),
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
        if let Some(err) = self
            .availability
            .and_then(|availability| availability.error(spec, self.field_name))
        {
            return Err(err);
        }

        if let Some(field) = self.field.as_ref() {
            if let Some(err) = spec.ctx_field_access_error(field) {
                return Err(err);
            }
        }

        let write_target = self.target.resolve(spec, self.field_name, index)?;
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
                    CtxWriteTarget::CgroupSockAddrSunPath => unreachable!(),
                },
            )),
            ContextWriteTargetSpec::SysctlNewValue => None,
            ContextWriteTargetSpec::SockoptOptvalByte => None,
            ContextWriteTargetSpec::AssignSocket => None,
            ContextWriteTargetSpec::CgroupSockAddrSunPath => None,
        }
    }

    fn store_target_error(&self, spec: &ProgramSpec) -> Option<String> {
        self.availability
            .and_then(|availability| availability.error(spec, self.field_name))
            .or_else(|| {
                self.field
                    .as_ref()
                    .and_then(|field| spec.ctx_field_access_error(field))
            })
    }

    fn representative_index(&self) -> Option<usize> {
        self.target.requires_indexed_assignment().then_some(0)
    }

    fn is_available(&self, spec: &ProgramSpec) -> bool {
        self.resolve_write_target(spec, self.representative_index())
            .is_ok()
    }

    fn minimum_kernel(&self, spec: &ProgramSpec) -> Option<(&'static str, &'static str)> {
        let target = spec.target_string();
        let field_floor = self.field.as_ref().and_then(|field| {
            ContextFieldCompatibilityRequirement::for_field_on_program_target(
                field,
                Some(spec.program_type()),
                Some(target.as_str()),
            )
            .map(|requirement| {
                (
                    requirement.minimum_kernel(),
                    requirement.minimum_kernel_source(),
                )
            })
        });
        let target_floor = self
            .target
            .compatibility_requirement()
            .and_then(|requirement| {
                Some((
                    requirement.minimum_kernel()?,
                    requirement.minimum_kernel_source()?,
                ))
            });

        later_kernel_floor(field_floor, target_floor)
    }

    fn surface(&self, spec: &ProgramSpec) -> ContextWriteSurface {
        let (minimum_kernel, minimum_kernel_source) = self
            .minimum_kernel(spec)
            .map(|(minimum_kernel, minimum_kernel_source)| {
                (Some(minimum_kernel), Some(minimum_kernel_source))
            })
            .unwrap_or((None, None));

        ContextWriteSurface {
            field_name: self.field_name,
            kind: self.target.kind(),
            indexed: self.target.requires_indexed_assignment(),
            minimum_kernel,
            minimum_kernel_source,
            helper: self.target.backing_helper(),
            kfunc: self.target.backing_kfunc(),
        }
    }
}

fn later_kernel_floor(
    left: Option<(&'static str, &'static str)>,
    right: Option<(&'static str, &'static str)>,
) -> Option<(&'static str, &'static str)> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if ContextFieldCompatibilityRequirement::kernel_version_at_least(left.0, right.0) {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(floor), None) | (None, Some(floor)) => Some(floor),
        (None, None) => None,
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
        "queue_mapping",
        CtxField::QueueMapping,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbQueueMapping),
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

const LWT_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
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
    ContextWriteSurfaceSpec::store_field(
        "bound_dev_if",
        CtxField::BoundDevIf,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockBoundDevIf),
    )
    .with_availability(ContextWriteAvailability::CgroupSockCreateReleaseOnly),
    ContextWriteSurfaceSpec::store_field(
        "mark",
        CtxField::SockMark,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::CgroupSockMark),
    )
    .with_availability(ContextWriteAvailability::CgroupSockCreateReleaseOnly),
    ContextWriteSurfaceSpec::store_field(
        "priority",
        CtxField::SockPriority,
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
    ContextWriteSurfaceSpec::special_write_field(
        "optval",
        CtxField::SockoptOptval,
        ContextWriteTargetSpec::SockoptOptvalByte,
    ),
];

const CGROUP_SOCK_ADDR_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::special_write(
        "sun_path",
        ContextWriteTargetSpec::CgroupSockAddrSunPath,
    )
    .with_availability(ContextWriteAvailability::CgroupSockAddrUnixOnly),
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
        program_type: EbpfProgramType::Tcx,
        surfaces: TC_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::Netkit,
        surfaces: TC_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::TcAction,
        surfaces: TC_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::LwtIn,
        surfaces: LWT_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::LwtOut,
        surfaces: LWT_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::LwtXmit,
        surfaces: LWT_CTX_WRITE_SURFACES,
    },
    ProgramContextWriteSurfaceSpec {
        program_type: EbpfProgramType::LwtSeg6Local,
        surfaces: LWT_CTX_WRITE_SURFACES,
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
            CtxStoreTarget::SockOpsReply => Some(CtxField::SockOpsReply),
            CtxStoreTarget::SockOpsReplyLong(_) => Some(CtxField::SockOpsReplyLong),
            CtxStoreTarget::SockOpsCbFlags => Some(CtxField::SockOpsCbFlags),
            CtxStoreTarget::SockOpsSkTxhash => Some(CtxField::SockOpsSkTxhash),
            CtxStoreTarget::CgroupSockBoundDevIf => Some(CtxField::BoundDevIf),
            CtxStoreTarget::CgroupSockMark => Some(CtxField::SockMark),
            CtxStoreTarget::CgroupSockPriority => Some(CtxField::SockPriority),
            CtxStoreTarget::SkbMark => Some(CtxField::SockMark),
            CtxStoreTarget::SkbQueueMapping => Some(CtxField::QueueMapping),
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
        let attach_shape = self.attach_shape();
        if attach_shape.is_cgroup_sock() {
            Some(CGROUP_SOCK_CTX_WRITE_SURFACES)
        } else if attach_shape.is_cgroup_sockopt() {
            Some(CGROUP_SOCKOPT_CTX_WRITE_SURFACES)
        } else if attach_shape.cgroup_sock_addr().is_some() {
            Some(CGROUP_SOCK_ADDR_CTX_WRITE_SURFACES)
        } else {
            program_ctx_write_surfaces(self.program_type())
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

        if let Some(err) = self
            .program_type()
            .base_ctx_store_target_error(store_target)
        {
            return Some(err);
        }

        if let Some(field) = store_target.ctx_field() {
            return self
                .ctx_field_access_error(&field)
                .or_else(|| Some(store_target.missing_context_error().to_string()));
        }

        None
    }

    pub(crate) fn ctx_write_surfaces_for_spec(&self) -> Vec<ContextWriteSurface> {
        self.ctx_write_surfaces()
            .unwrap_or(&[])
            .iter()
            .filter(|surface| surface.is_available(self))
            .map(|surface| surface.surface(self))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn assert_unique_write_surface_names(table_name: &str, surfaces: &[ContextWriteSurfaceSpec]) {
        let mut names = HashSet::new();

        for surface in surfaces {
            assert!(
                names.insert(surface.field_name),
                "duplicate writable context field '{}' in {table_name}",
                surface.field_name
            );
        }
    }

    fn assert_write_surface_field_names_resolve(
        program_type: EbpfProgramType,
        table_name: &str,
        surfaces: &[ContextWriteSurfaceSpec],
    ) {
        for surface in surfaces {
            let Some(field) = surface.field.as_ref() else {
                continue;
            };
            assert_eq!(
                program_type.resolve_ctx_field_name(surface.field_name),
                Ok(field.clone()),
                "writable context field '{}' in {table_name} should resolve to {:?} for {program_type:?}",
                surface.field_name,
                field
            );
        }
    }

    #[test]
    fn test_context_write_surface_tables_are_unique() {
        for (table_name, surfaces) in [
            (
                "socket_filter context write surfaces",
                SOCKET_FILTER_CTX_WRITE_SURFACES,
            ),
            ("tc context write surfaces", TC_CTX_WRITE_SURFACES),
            ("sk_skb context write surfaces", SK_SKB_CTX_WRITE_SURFACES),
            ("lwt context write surfaces", LWT_CTX_WRITE_SURFACES),
            (
                "cgroup_skb context write surfaces",
                CGROUP_SKB_CTX_WRITE_SURFACES,
            ),
            (
                "cgroup_sock context write surfaces",
                CGROUP_SOCK_CTX_WRITE_SURFACES,
            ),
            (
                "cgroup_sysctl context write surfaces",
                CGROUP_SYSCTL_CTX_WRITE_SURFACES,
            ),
            (
                "sock_ops context write surfaces",
                SOCK_OPS_CTX_WRITE_SURFACES,
            ),
            (
                "cgroup_sockopt context write surfaces",
                CGROUP_SOCKOPT_CTX_WRITE_SURFACES,
            ),
            (
                "cgroup_sock_addr context write surfaces",
                CGROUP_SOCK_ADDR_CTX_WRITE_SURFACES,
            ),
            (
                "sk_lookup context write surfaces",
                SK_LOOKUP_CTX_WRITE_SURFACES,
            ),
        ] {
            assert_unique_write_surface_names(table_name, surfaces);
        }

        let mut program_types = HashSet::new();
        for surface in PROGRAM_CTX_WRITE_SURFACES {
            assert!(
                program_types.insert(surface.program_type),
                "duplicate program write surface for {:?}",
                surface.program_type
            );
        }
    }

    #[test]
    fn test_context_write_surface_field_names_resolve() {
        for surface in PROGRAM_CTX_WRITE_SURFACES {
            assert_write_surface_field_names_resolve(
                surface.program_type,
                "program context write surfaces",
                surface.surfaces,
            );
        }

        for (program_type, table_name, surfaces) in [
            (
                EbpfProgramType::CgroupSock,
                "cgroup_sock context write surfaces",
                CGROUP_SOCK_CTX_WRITE_SURFACES,
            ),
            (
                EbpfProgramType::CgroupSockopt,
                "cgroup_sockopt context write surfaces",
                CGROUP_SOCKOPT_CTX_WRITE_SURFACES,
            ),
            (
                EbpfProgramType::CgroupSockAddr,
                "cgroup_sock_addr context write surfaces",
                CGROUP_SOCK_ADDR_CTX_WRITE_SURFACES,
            ),
        ] {
            assert_write_surface_field_names_resolve(program_type, table_name, surfaces);
        }
    }

    #[test]
    fn test_context_write_surfaces_for_spec_filter_target_specific_availability() {
        let tc_ingress = ProgramSpec::parse("tc:lo:ingress").expect("tc ingress spec should parse");
        let tc_ingress_writes = tc_ingress.ctx_write_surfaces_for_spec();
        assert!(tc_ingress_writes.iter().any(|surface| {
            surface.field_name == "sk" && surface.kind == "assign-socket" && !surface.indexed
        }));
        assert!(
            tc_ingress_writes
                .iter()
                .any(|surface| surface.field_name == "cb" && surface.indexed)
        );

        let tc_egress = ProgramSpec::parse("tc:lo:egress").expect("tc egress spec should parse");
        let tc_egress_writes = tc_egress.ctx_write_surfaces_for_spec();
        assert!(
            !tc_egress_writes
                .iter()
                .any(|surface| surface.field_name == "sk"),
            "ctx.sk assignment is ingress-only"
        );

        let cgroup_skb_ingress = ProgramSpec::parse("cgroup_skb:/sys/fs/cgroup:ingress")
            .expect("cgroup_skb ingress spec should parse");
        assert!(
            !cgroup_skb_ingress
                .ctx_write_surfaces_for_spec()
                .iter()
                .any(|surface| surface.field_name == "tstamp"),
            "ctx.tstamp assignment is egress-only for cgroup_skb"
        );
    }
}
