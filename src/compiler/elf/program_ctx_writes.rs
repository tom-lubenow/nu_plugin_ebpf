use super::{CtxWriteTarget, EbpfProgramType, ProgramContextFamily};
use crate::compiler::mir::{CtxField, CtxStoreTarget};
use crate::program_spec::ProgramSpec;

fn word_index(field_name: &str, index: usize) -> Result<u8, String> {
    let index = u8::try_from(index)
        .map_err(|_| format!("ctx.{field_name} index must be in 0..=3, got {index}"))?;
    if index >= 4 {
        return Err(format!(
            "ctx.{field_name} index must be in 0..=3, got {index}"
        ));
    }
    Ok(index)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextStoreTargetSpec {
    Fixed(CtxStoreTarget),
    SockOpsReplyLongWord,
    CgroupSockAddrUserIp6Word,
    CgroupSockAddrMsgSrcIp6Word,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextWriteTargetSpec {
    Store(ContextStoreTargetSpec),
    SockoptOptvalByte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextWriteAvailability {
    CgroupSockoptSetOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgramCtxWriteSurfaceFamilyRequirement {
    SkbContext,
    CgroupSysctl,
    SockOps,
    CgroupSockopt,
    CgroupSockAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContextWriteSurfaceSpec {
    field_name: &'static str,
    field: Option<CtxField>,
    target: ContextWriteTargetSpec,
    availability: Option<ContextWriteAvailability>,
}

#[derive(Debug, Clone, Copy)]
struct ProgramCtxWriteSurfaceFamilySpec {
    requirement: ProgramCtxWriteSurfaceFamilyRequirement,
    surfaces: &'static [ContextWriteSurfaceSpec],
}

impl ContextStoreTargetSpec {
    fn resolve(&self, field_name: &str, index: Option<usize>) -> Result<CtxStoreTarget, String> {
        match self {
            Self::Fixed(target) => match index {
                Some(_) => Err(format!(
                    "ctx.{field_name} does not support indexed assignment"
                )),
                None => Ok(target.clone()),
            },
            Self::SockOpsReplyLongWord => match index {
                Some(index) => word_index(field_name, index).map(CtxStoreTarget::SockOpsReplyLong),
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
            Self::CgroupSockAddrUserIp6Word => match index {
                Some(index) => {
                    word_index(field_name, index).map(CtxStoreTarget::CgroupSockAddrUserIp6Word)
                }
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
            Self::CgroupSockAddrMsgSrcIp6Word => match index {
                Some(index) => {
                    word_index(field_name, index).map(CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word)
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
            (Self::CgroupSockAddrUserIp6Word, CtxStoreTarget::CgroupSockAddrUserIp6Word(_)) => true,
            (Self::CgroupSockAddrMsgSrcIp6Word, CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_)) => {
                true
            }
            _ => false,
        }
    }
}

impl ContextWriteTargetSpec {
    fn resolve(&self, field_name: &str, index: Option<usize>) -> Result<CtxWriteTarget, String> {
        match self {
            Self::Store(target) => target
                .resolve(field_name, index)
                .map(CtxWriteTarget::StoreField),
            Self::SockoptOptvalByte => match index {
                Some(index) => Ok(CtxWriteTarget::SockoptOptvalByte(index)),
                None => Err(format!(
                    "ctx.{field_name} assignment requires a fixed index, e.g. $ctx.{field_name}.0 = ..."
                )),
            },
        }
    }

    fn matches_store_target(&self, target: &CtxStoreTarget) -> bool {
        match self {
            Self::Store(spec) => spec.matches_target(target),
            Self::SockoptOptvalByte => false,
        }
    }
}

impl ContextWriteAvailability {
    fn error(&self, spec: &ProgramSpec, field_name: &str) -> Option<String> {
        match self {
            Self::CgroupSockoptSetOnly => match spec {
                ProgramSpec::CgroupSockopt { target } if target.is_get() => Some(format!(
                    "ctx.{field_name} is only writable on cgroup_sockopt:set hooks"
                )),
                _ => None,
            },
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

        let write_target = self.target.resolve(self.field_name, index)?;
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
                    CtxWriteTarget::SockoptOptvalByte(_) => unreachable!(),
                },
            )),
            ContextWriteTargetSpec::SockoptOptvalByte => None,
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

impl ProgramCtxWriteSurfaceFamilyRequirement {
    fn matches_spec(&self, spec: &ProgramSpec) -> bool {
        match self {
            Self::SkbContext => spec.program_type().supports_skb_ctx_fields(),
            Self::CgroupSysctl => matches!(spec, ProgramSpec::CgroupSysctl { .. }),
            Self::SockOps => matches!(spec, ProgramSpec::SockOps { .. }),
            Self::CgroupSockopt => matches!(spec, ProgramSpec::CgroupSockopt { .. }),
            Self::CgroupSockAddr => matches!(spec, ProgramSpec::CgroupSockAddr { .. }),
        }
    }
}

const SKB_TSTAMP_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] =
    &[ContextWriteSurfaceSpec::store_field(
        "tstamp",
        CtxField::Tstamp,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SkbTstamp),
    )];

const CGROUP_SYSCTL_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] =
    &[ContextWriteSurfaceSpec::store_field(
        "file_pos",
        CtxField::SysctlFilePos,
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SysctlFilePos),
    )];

const SOCK_OPS_CTX_WRITE_SURFACES: &[ContextWriteSurfaceSpec] = &[
    ContextWriteSurfaceSpec::named_store(
        "reply",
        ContextStoreTargetSpec::Fixed(CtxStoreTarget::SockOpsReply),
    ),
    ContextWriteSurfaceSpec::named_store("replylong", ContextStoreTargetSpec::SockOpsReplyLongWord),
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
];

const PROGRAM_CTX_WRITE_SURFACE_FAMILIES: &[ProgramCtxWriteSurfaceFamilySpec] = &[
    ProgramCtxWriteSurfaceFamilySpec {
        requirement: ProgramCtxWriteSurfaceFamilyRequirement::SkbContext,
        surfaces: SKB_TSTAMP_CTX_WRITE_SURFACES,
    },
    ProgramCtxWriteSurfaceFamilySpec {
        requirement: ProgramCtxWriteSurfaceFamilyRequirement::CgroupSysctl,
        surfaces: CGROUP_SYSCTL_CTX_WRITE_SURFACES,
    },
    ProgramCtxWriteSurfaceFamilySpec {
        requirement: ProgramCtxWriteSurfaceFamilyRequirement::SockOps,
        surfaces: SOCK_OPS_CTX_WRITE_SURFACES,
    },
    ProgramCtxWriteSurfaceFamilySpec {
        requirement: ProgramCtxWriteSurfaceFamilyRequirement::CgroupSockopt,
        surfaces: CGROUP_SOCKOPT_CTX_WRITE_SURFACES,
    },
    ProgramCtxWriteSurfaceFamilySpec {
        requirement: ProgramCtxWriteSurfaceFamilyRequirement::CgroupSockAddr,
        surfaces: CGROUP_SOCK_ADDR_CTX_WRITE_SURFACES,
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

impl CtxStoreTarget {
    pub(crate) fn ctx_field(&self) -> Option<CtxField> {
        match self {
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => None,
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
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => {
                Some(ProgramContextFamily::SockOps)
            }
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
    fn ctx_write_surface_for_name(&self, field_name: &str) -> Option<ContextWriteSurfaceSpec> {
        PROGRAM_CTX_WRITE_SURFACE_FAMILIES
            .iter()
            .filter(|family| family.requirement.matches_spec(self))
            .find_map(|family| find_ctx_write_surface(field_name, family.surfaces))
    }

    fn ctx_write_surface_for_store_target(
        &self,
        target: &CtxStoreTarget,
    ) -> Option<ContextWriteSurfaceSpec> {
        PROGRAM_CTX_WRITE_SURFACE_FAMILIES
            .iter()
            .filter(|family| family.requirement.matches_spec(self))
            .find_map(|family| find_ctx_store_surface(target, family.surfaces))
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
        self.ctx_write_surface_for_store_target(store_target)
            .and_then(|surface| surface.store_target_error(self))
            .or_else(|| {
                self.program_type()
                    .base_ctx_store_target_error(store_target)
            })
    }
}
