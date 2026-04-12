use super::CtxWriteTarget;
use crate::compiler::mir::CtxStoreTarget;
use crate::program_spec::{CgroupSockoptTarget, ProgramSpec, SockOpsTarget};

fn sock_ops_word_index(field_name: &str, index: usize) -> Result<u8, String> {
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
                Some(sock_ops_word_index("replylong", index).map(CtxStoreTarget::SockOpsReplyLong))
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
