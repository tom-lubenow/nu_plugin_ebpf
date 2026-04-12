use crate::compiler::ProbeContext;
use crate::compiler::mir::CtxField;

pub(crate) fn resolve_probe_ctx_field_name(
    probe_ctx: &ProbeContext,
    field_name: &str,
) -> Result<CtxField, String> {
    if !probe_ctx.is_tracepoint() {
        return probe_ctx.probe_type.resolve_ctx_field_name(field_name);
    }

    probe_ctx
        .probe_type
        .resolve_tracepoint_ctx_field_name(field_name)
}
