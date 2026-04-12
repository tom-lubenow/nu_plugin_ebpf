use super::CtxWriteTarget;
use crate::compiler::mir::{CtxField, CtxStoreTarget};
use crate::program_spec::{CgroupSockAddrTarget, CgroupSockoptTarget, ProgramSpec, SockOpsTarget};

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

impl SockOpsTarget {
    fn resolve_special_ctx_store_target(
        &self,
        field_name: &str,
        index: Option<usize>,
    ) -> Option<Result<CtxStoreTarget, String>> {
        match (field_name, index) {
            ("reply", None) => Some(Ok(CtxStoreTarget::SockOpsReply)),
            ("reply", Some(_)) => Some(Err("ctx.reply does not support indexed assignment".into())),
            ("replylong", Some(index)) => {
                Some(word_index("replylong", index).map(CtxStoreTarget::SockOpsReplyLong))
            }
            ("replylong", None) => Some(Err(
                "ctx.replylong assignment requires a fixed index, e.g. $ctx.replylong.0 = ..."
                    .into(),
            )),
            _ => None,
        }
    }
}

impl CgroupSockoptTarget {
    fn resolve_ctx_store_target_for_field(
        &self,
        field: &CtxField,
        index: Option<usize>,
    ) -> Option<Result<CtxStoreTarget, String>> {
        match (field, index) {
            (CtxField::SockoptRetval, None) => Some(if self.is_get() {
                Ok(CtxStoreTarget::SockoptRetval)
            } else {
                Err("ctx.sockopt_retval is only available on cgroup_sockopt:get hooks".into())
            }),
            (CtxField::SockoptRetval, Some(_)) => Some(Err(
                "ctx.sockopt_retval does not support indexed assignment".into(),
            )),
            (CtxField::SockoptLevel, None) => Some(if self.is_get() {
                Err("ctx.level is only writable on cgroup_sockopt:set hooks".into())
            } else {
                Ok(CtxStoreTarget::SockoptLevel)
            }),
            (CtxField::SockoptLevel, Some(_)) => {
                Some(Err("ctx.level does not support indexed assignment".into()))
            }
            (CtxField::SockoptOptname, None) => Some(if self.is_get() {
                Err("ctx.optname is only writable on cgroup_sockopt:set hooks".into())
            } else {
                Ok(CtxStoreTarget::SockoptOptname)
            }),
            (CtxField::SockoptOptname, Some(_)) => {
                Some(Err("ctx.optname does not support indexed assignment".into()))
            }
            (CtxField::SockoptOptlen, None) => Some(Ok(CtxStoreTarget::SockoptOptlen)),
            (CtxField::SockoptOptlen, Some(_)) => {
                Some(Err("ctx.optlen does not support indexed assignment".into()))
            }
            _ => None,
        }
    }

    fn resolve_special_ctx_write_target(
        &self,
        field_name: &str,
        index: Option<usize>,
    ) -> Option<Result<CtxWriteTarget, String>> {
        if field_name != "optval" {
            return None;
        }

        Some(match index {
            Some(index) => Ok(CtxWriteTarget::SockoptOptvalByte(index)),
            None => {
                Err("ctx.optval assignment requires a fixed index, e.g. $ctx.optval.0 = ...".into())
            }
        })
    }
}

impl CgroupSockAddrTarget {
    fn resolve_ctx_store_target_for_field(
        &self,
        field: &CtxField,
        index: Option<usize>,
    ) -> Option<Result<CtxStoreTarget, String>> {
        match (field, index) {
            (CtxField::UserIp4, None) => Some(Ok(CtxStoreTarget::CgroupSockAddrUserIp4)),
            (CtxField::UserIp4, Some(_)) => Some(Err(
                "ctx.user_ip4 does not support indexed assignment".into(),
            )),
            (CtxField::UserIp6, Some(index)) => {
                Some(word_index("user_ip6", index).map(CtxStoreTarget::CgroupSockAddrUserIp6Word))
            }
            (CtxField::UserIp6, None) => Some(Err(
                "ctx.user_ip6 assignment requires a fixed index, e.g. $ctx.user_ip6.0 = ...".into(),
            )),
            (CtxField::UserPort, None) => Some(Ok(CtxStoreTarget::CgroupSockAddrUserPort)),
            (CtxField::UserPort, Some(_)) => Some(Err(
                "ctx.user_port does not support indexed assignment".into(),
            )),
            (CtxField::MsgSrcIp4, None) => Some(Ok(CtxStoreTarget::CgroupSockAddrMsgSrcIp4)),
            (CtxField::MsgSrcIp4, Some(_)) => Some(Err(
                "ctx.msg_src_ip4 does not support indexed assignment".into(),
            )),
            (CtxField::MsgSrcIp6, Some(index)) => Some(
                word_index("msg_src_ip6", index).map(CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word),
            ),
            (CtxField::MsgSrcIp6, None) => Some(Err(
                "ctx.msg_src_ip6 assignment requires a fixed index, e.g. $ctx.msg_src_ip6.0 = ..."
                    .into(),
            )),
            _ => None,
        }
    }
}

impl ProgramSpec {
    pub(crate) fn resolve_special_ctx_store_target(
        &self,
        field_name: &str,
        index: Option<usize>,
    ) -> Option<Result<CtxStoreTarget, String>> {
        match self {
            ProgramSpec::SockOps { target } => {
                target.resolve_special_ctx_store_target(field_name, index)
            }
            _ => None,
        }
    }

    pub(crate) fn resolve_ctx_store_target_for_field(
        &self,
        field: &CtxField,
        index: Option<usize>,
    ) -> Option<Result<CtxStoreTarget, String>> {
        match self {
            ProgramSpec::CgroupSysctl { .. } => match (field, index) {
                (CtxField::SysctlFilePos, None) => Some(Ok(CtxStoreTarget::SysctlFilePos)),
                (CtxField::SysctlFilePos, Some(_)) => Some(Err(
                    "ctx.file_pos does not support indexed assignment".into(),
                )),
                _ => None,
            },
            ProgramSpec::CgroupSockopt { target } => {
                target.resolve_ctx_store_target_for_field(field, index)
            }
            ProgramSpec::CgroupSockAddr { target } => {
                target.resolve_ctx_store_target_for_field(field, index)
            }
            _ => None,
        }
    }

    pub(crate) fn resolve_special_ctx_write_target(
        &self,
        field_name: &str,
        index: Option<usize>,
    ) -> Option<Result<CtxWriteTarget, String>> {
        if let Some(result) = self.resolve_special_ctx_store_target(field_name, index) {
            return Some(result.map(CtxWriteTarget::StoreField));
        }

        match self {
            ProgramSpec::CgroupSockopt { target } => {
                target.resolve_special_ctx_write_target(field_name, index)
            }
            _ => None,
        }
    }
}
