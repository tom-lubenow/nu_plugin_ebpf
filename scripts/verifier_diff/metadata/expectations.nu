const EXPECTATIONS_DIR = (path self | path dirname | path join expectations)
const PROGRAM_CONTEXT_FIELD_EXPECTATION_CHUNKS_DIR = (
    $EXPECTATIONS_DIR | path join program_context_fields
)

source ($EXPECTATIONS_DIR | path join context_fields.nu)
source ($EXPECTATIONS_DIR | path join context_field_helpers.nu)
source ($EXPECTATIONS_DIR | path join context_projection_helpers.nu)
source ($EXPECTATIONS_DIR | path join program_surfaces.nu)
source ($EXPECTATIONS_DIR | path join program_helper_core.nu)
source ($EXPECTATIONS_DIR | path join program_helper_socket.nu)
source ($EXPECTATIONS_DIR | path join program_helper_timer.nu)
source ($EXPECTATIONS_DIR | path join program_helpers.nu)
source ($EXPECTATIONS_DIR | path join program_kfunc_sock_addr.nu)
source ($EXPECTATIONS_DIR | path join program_kfuncs.nu)
source ($EXPECTATIONS_DIR | path join program_kfunc_details.nu)
source ($EXPECTATIONS_DIR | path join program_callbacks.nu)

def parse-program-context-field-expectation-chunk [path: path] {
    open --raw $path | from nuon
}

let PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS = (
    glob ($PROGRAM_CONTEXT_FIELD_EXPECTATION_CHUNKS_DIR | path join "program_context_fields_*.nu")
    | sort
    | each {|path| parse-program-context-field-expectation-chunk $path }
    | reduce --fold [] {|chunk, acc| $acc | append $chunk }
)
