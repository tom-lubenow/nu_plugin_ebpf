const EXPECTATIONS_DIR = (path self | path dirname | path join expectations)

source ($EXPECTATIONS_DIR | path join context_fields.nu)
source ($EXPECTATIONS_DIR | path join program_context_fields_1.nu)
source ($EXPECTATIONS_DIR | path join program_context_fields_2.nu)
source ($EXPECTATIONS_DIR | path join program_context_fields_3.nu)
source ($EXPECTATIONS_DIR | path join program_context_fields_4.nu)
source ($EXPECTATIONS_DIR | path join program_surfaces.nu)
source ($EXPECTATIONS_DIR | path join program_helpers.nu)
source ($EXPECTATIONS_DIR | path join program_kfuncs.nu)
source ($EXPECTATIONS_DIR | path join program_callbacks.nu)

let PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS = (
    $PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS_1
    | append $PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS_2
    | append $PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS_3
    | append $PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS_4
)
