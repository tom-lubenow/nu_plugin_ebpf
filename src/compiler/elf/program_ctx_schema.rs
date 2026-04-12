use super::CtxField;
use crate::compiler::ctx_field_schema::{
    ContextFieldProjectionSpec, ContextFieldTypeSpec, program_type_ctx_field_projection_spec,
    program_type_ctx_field_type_spec,
};
use crate::program_spec::ProgramSpec;

impl ProgramSpec {
    pub(crate) fn ctx_field_type_spec(&self, field: &CtxField) -> Option<ContextFieldTypeSpec> {
        program_type_ctx_field_type_spec(self.program_type(), field)
    }

    pub(crate) fn ctx_field_projection_spec(
        &self,
        field: &CtxField,
    ) -> Option<ContextFieldProjectionSpec> {
        program_type_ctx_field_projection_spec(self.program_type(), field)
    }
}
