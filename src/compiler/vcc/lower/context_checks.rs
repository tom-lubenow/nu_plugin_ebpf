use super::*;
use crate::compiler::mir::CtxStoreTarget;

impl<'a> VccLowerer<'a> {
    pub(super) fn verify_ctx_field_load(&self, field: &CtxField) -> Result<(), VccError> {
        if let Some(ctx) = self.probe_ctx
            && let Err(err) = ctx.validate_ctx_field_access(field)
        {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                err.to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn verify_ctx_field_store(
        &self,
        target: &CtxStoreTarget,
        ty: &MirType,
    ) -> Result<(), VccError> {
        if *ty != target.value_type() {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                target.type_error_message(ty),
            ));
        }
        let Some(ctx) = self.probe_ctx else {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                target.missing_context_error(),
            ));
        };
        ctx.validate_ctx_store_target(target)
            .map_err(|err| VccError::new(VccErrorKind::UnsupportedInstruction, err.to_string()))
    }
}
