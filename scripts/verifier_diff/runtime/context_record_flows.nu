const VERIFIER_DIFF_CONTEXT_RECORD_FLOWS_RUNTIME_DIR = (path self | path dirname)
source ($VERIFIER_DIFF_CONTEXT_RECORD_FLOWS_RUNTIME_DIR | path join context_record_parse_helpers.nu)

source ($VERIFIER_DIFF_CONTEXT_RECORD_FLOWS_RUNTIME_DIR | path join context_record_field_ops.nu)

def record-pipeline-flow-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    let parts = (split-pipeline-segments $raw)
    if ($parts | length) <= 1 {
        return []
    }

    mut fields = (
        record-pipeline-input-context-fields
            $raw
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
            $aliases
    )
    mut field_order = (record-pipeline-input-field-order $raw $aliases)
    mut null_fields = (record-pipeline-input-null-fields $raw)

    for segment in ($parts | skip 1) {
        let trimmed = ($segment | str trim)

        for command in [insert update upsert] {
            if not (($trimmed == $command) or ($trimmed | str starts-with $"($command) ")) {
                continue
            }

            let tail = ($trimmed | str substring ($command | str length).. | str trim)
            let field_value = (record-command-field-value $tail)
            if $field_value == null {
                continue
            }

            let root = (
                context-root-from-record-value-token
                    $field_value.value
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            $fields = (replace-record-context-field $fields $field_value.field $root)
            $field_order = (upsert-record-field-order $field_order $field_value.field)
            $null_fields = if (value-token-null? $field_value.value) {
                append-field-name $null_fields $field_value.field
            } else {
                remove-field-name $null_fields $field_value.field
            }
        }

        if ($trimmed | str starts-with "merge ") {
            let merge_arg = (record-literal-argument ($trimmed | str substring 5.. | str trim))
            if $merge_arg == null {
                continue
            }

            let merge_fields = (record-literal-field-names $merge_arg)
            for field in $merge_fields {
                $fields = (remove-record-context-field $fields $field)
                $null_fields = (remove-field-name $null_fields $field)
            }
            $fields = (unique-record-context-fields (
                $fields
                | append (
                    record-literal-context-fields
                        $merge_arg
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
            ))
            for field in (record-literal-null-field-names $merge_arg) {
                $null_fields = (append-field-name $null_fields $field)
            }
            $field_order = (merge-record-field-order $field_order $merge_fields)
        }

        if ($trimmed | str starts-with "select ") {
            let selected = (record-field-name-list ($trimmed | str substring 6..))
            $fields = ($fields | where {|field| $field.field in $selected })
            $field_order = $selected
            $null_fields = ($null_fields | where {|field| $field in $selected })
        }

        if ($trimmed | str starts-with "reject ") {
            let rejected = (record-field-name-list ($trimmed | str substring 6..))
            $fields = ($fields | where {|field| $field.field not-in $rejected })
            $null_fields = ($null_fields | where {|field| $field not-in $rejected })
            if $field_order != null {
                $field_order = ($field_order | where {|field| $field not-in $rejected })
            }
        }

        if ($trimmed | str starts-with "rename ") {
            let rename_names = (record-field-name-list ($trimmed | str substring 6..))
            $fields = (rename-record-context-fields $fields $field_order $rename_names)
            $null_fields = (rename-record-field-order $null_fields $rename_names)
            $field_order = (rename-record-field-order $field_order $rename_names)
        }

        if ($trimmed | str starts-with "default ") {
            let field_value = (record-default-field-value ($trimmed | str substring 7..))
            if $field_value == null {
                continue
            }

            let field_exists = ($field_order != null and $field_value.field in $field_order)
            let can_fill_field = (
                not (has-record-context-field? $fields $field_value.field)
                and (not $field_exists or $field_value.field in $null_fields)
            )
            if not $can_fill_field {
                continue
            }

            let root = (
                context-root-from-record-value-token
                    $field_value.value
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            $fields = (replace-record-context-field $fields $field_value.field $root)
            $field_order = (upsert-record-field-order $field_order $field_value.field)
            $null_fields = if (value-token-null? $field_value.value) {
                append-field-name $null_fields $field_value.field
            } else {
                remove-field-name $null_fields $field_value.field
            }
        }
    }

    unique-record-context-fields $fields
}

def record-pipeline-flow-context-bindings [line: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    mut bindings = []

    for assignment in (declaration-assignments $line) {
        for field in (
            record-pipeline-flow-context-fields
                (declaration-rhs-token $assignment)
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
                $aliases
        ) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: ($field | get -o root | default "")
            })
        }
    }

    $bindings
}
