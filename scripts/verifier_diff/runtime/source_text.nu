const VERIFIER_DIFF_SOURCE_TEXT_RUNTIME_DIR = (path self | path dirname)

source ($VERIFIER_DIFF_SOURCE_TEXT_RUNTIME_DIR | path join source_text_tokens.nu)
source ($VERIFIER_DIFF_SOURCE_TEXT_RUNTIME_DIR | path join source_text_commands.nu)
source ($VERIFIER_DIFF_SOURCE_TEXT_RUNTIME_DIR | path join source_text_map_helpers.nu)
source ($VERIFIER_DIFF_SOURCE_TEXT_RUNTIME_DIR | path join source_text_kernel_features.nu)
