const VERIFIER_DIFF_SOURCE_TEXT_RUNTIME_DIR = (path self | path dirname)

def normalize-map-kind-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
}

def normalize-map-name-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def normalize-helper-name-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
}

def normalize-kfunc-name-token [token: string] {
    normalize-helper-name-token $token
}

def normalize-context-field-token [token: string] {
    $token
    | str trim
    | split row " "
    | first
    | split row "."
    | first
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def normalize-context-path-token [token: string] {
    $token
    | str trim
    | split row " "
    | first
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

source ($VERIFIER_DIFF_SOURCE_TEXT_RUNTIME_DIR | path join source_text_commands.nu)

def source-line-helper-call-name [line: string] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    let raw_helper = (($tails | first) | str trim | split row " " | first)
    normalize-helper-name-token $raw_helper
}

def helper-call-map-kind-entry [line: string] {
    let helper_name = (source-line-helper-call-name $line)
    if $helper_name == null {
        return null
    }

    let fixed_matches = ($HELPER_CALL_FIXED_MAP_KIND_FEATURES | where {|entry| $entry.helper == $helper_name })
    if not ($fixed_matches | is-empty) {
        return ($fixed_matches | first)
    }

    let explicit_matches = ($HELPER_CALL_EXPLICIT_MAP_KIND_FEATURES | where {|entry| $entry.helper == $helper_name })
    if not ($explicit_matches | is-empty) {
        return ($explicit_matches | first)
    }

    null
}

def source-line-helper-call-map-name [line: string entry] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    let tokens = (
        ($tails | first)
        | str trim
        | split row " "
        | each {|token| $token | str trim }
        | where {|token| $token != "" }
    )
    let arg_idx = (($entry | get map_arg) + 1)
    if $arg_idx >= ($tokens | length) {
        return null
    }

    let name = (normalize-map-name-token ($tokens | get $arg_idx))
    if $name == "" or ($name | str starts-with "$") {
        null
    } else {
        $name
    }
}

def helper-call-effective-map-kind [line: string bindings] {
    let entry = (helper-call-map-kind-entry $line)
    if $entry == null {
        return null
    }

    let fixed_kind = ($entry | get -o kind)
    if $fixed_kind != null and $fixed_kind != "" {
        return $fixed_kind
    }

    let supported_kinds = ($entry | get -o kinds | default [])
    let explicit_kind = (source-line-map-kind $line "")
    if $explicit_kind != "" {
        if $explicit_kind in $supported_kinds {
            return $explicit_kind
        }
        return null
    }

    let map_name = (source-line-helper-call-map-name $line $entry)
    let inferred_kind = (map-kind-binding $bindings $map_name)
    if $inferred_kind != null and ($inferred_kind in $supported_kinds) {
        return $inferred_kind
    }

    null
}

def helper-call-map-kind-kernel-feature [line: string bindings] {
    let kind = (helper-call-effective-map-kind $line $bindings)
    if $kind == null or $kind == "" {
        return null
    }

    map-kind-kernel-feature $kind
}

def source-line-map-kind [line: string default_kind: string] {
    for raw_tail in (marker-tails-outside-simple-string $line "--kind ") {
        let raw_kind = ($raw_tail | str trim | split row " " | first)
        return (normalize-map-kind-token $raw_kind)
    }

    $default_kind
}

def source-line-command-map-name [line: string command: string] {
    let tails = (command-invocation-tails $line $command)
    if ($tails | is-empty) {
        return null
    }

    let raw_name = (($tails | first) | str trim | split row " " | first)
    let name = (normalize-map-name-token $raw_name)
    if $name == "" or ($name | str starts-with "$") {
        null
    } else {
        $name
    }
}

def source-line-map-kind-surface [line: string] {
    for command in [
        "map-define"
        "map-get"
        "map-put"
        "map-delete"
        "map-contains"
        "map-push"
        "map-peek"
        "map-pop"
        "redirect-map"
        "redirect-socket"
    ] {
        if (line-invokes-command? $line $command) {
            return {
                command: $command
                name: (source-line-command-map-name $line $command)
            }
        }
    }

    null
}

def map-command-default-kind [command: string] {
    if $command in ["map-define" "map-get" "map-put" "map-delete" "map-contains"] {
        "hash"
    } else {
        ""
    }
}

def map-kind-binding [bindings name] {
    if $name == null or $name == "" {
        return null
    }

    let matches = ($bindings | where {|entry| $entry.name == $name })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get kind
    }
}

def bind-map-kind [bindings name kind] {
    if $name == null or $name == "" or $kind == null or $kind == "" {
        return $bindings
    }

    $bindings
    | where {|entry| $entry.name != $name }
    | append { name: $name kind: $kind }
}

def source-line-effective-map-kind [line: string bindings] {
    let surface = (source-line-map-kind-surface $line)
    if $surface == null {
        return null
    }

    let explicit_kind = (source-line-map-kind $line "")
    if $explicit_kind != "" {
        return $explicit_kind
    }

    let name = ($surface | get name)
    if $name == null {
        return null
    }

    let inferred_kind = (map-kind-binding $bindings $name)
    if $inferred_kind != null {
        return $inferred_kind
    }

    let default_kind = (map-command-default-kind ($surface | get command))
    if $default_kind == "" {
        null
    } else {
        $default_kind
    }
}

def update-map-kind-bindings-for-line [bindings line: string] {
    let surface = (source-line-map-kind-surface $line)
    if $surface == null {
        return $bindings
    }

    let name = ($surface | get name)
    if $name == null {
        return $bindings
    }

    let kind = (source-line-effective-map-kind $line $bindings)
    bind-map-kind $bindings $name $kind
}

def update-helper-call-map-kind-bindings-for-line [bindings line: string] {
    let entry = (helper-call-map-kind-entry $line)
    if $entry == null {
        return $bindings
    }

    let name = (source-line-helper-call-map-name $line $entry)
    let kind = (helper-call-effective-map-kind $line $bindings)
    bind-map-kind $bindings $name $kind
}

def line-invokes-map-kind-surface? [line: string] {
    for command in [
        "map-define"
        "map-get"
        "map-put"
        "map-delete"
        "map-contains"
        "map-push"
        "map-peek"
        "map-pop"
        "redirect-map"
        "redirect-socket"
    ] {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def generic-map-lookup-kind? [kind: string] {
    $kind in [
        "hash"
        "array"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "per-cpu-array"
        "lru-per-cpu-hash"
    ]
}

def generic-map-update-kind? [kind: string] {
    $kind in [
        "hash"
        "array"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "per-cpu-array"
        "lru-per-cpu-hash"
    ]
}

def generic-map-delete-kind? [kind: string] {
    $kind in [
        "hash"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "lru-per-cpu-hash"
    ]
}

def local-storage-get-helper-kernel-feature [kind: string] {
    if $kind == "sk-storage" {
        return $KERNEL_FEATURE_BPF_SK_STORAGE_GET
    }
    if $kind == "inode-storage" {
        return $KERNEL_FEATURE_BPF_INODE_STORAGE_GET
    }
    if $kind == "task-storage" {
        return $KERNEL_FEATURE_BPF_TASK_STORAGE_GET
    }
    if $kind == "cgrp-storage" {
        return $KERNEL_FEATURE_BPF_CGRP_STORAGE_GET
    }

    null
}

def local-storage-delete-helper-kernel-feature [kind: string] {
    if $kind == "sk-storage" {
        return $KERNEL_FEATURE_BPF_SK_STORAGE_DELETE
    }
    if $kind == "inode-storage" {
        return $KERNEL_FEATURE_BPF_INODE_STORAGE_DELETE
    }
    if $kind == "task-storage" {
        return $KERNEL_FEATURE_BPF_TASK_STORAGE_DELETE
    }
    if $kind == "cgrp-storage" {
        return $KERNEL_FEATURE_BPF_CGRP_STORAGE_DELETE
    }

    null
}

def helper-kernel-feature [name: string] {
    let matches = ($HELPER_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if not ($matches | is-empty) {
        return ($matches | first | get feature)
    }

    let helper_ids = ($BPF_HELPER_IDS | where {|entry| $entry.name == $name })
    if ($helper_ids | is-empty) {
        return null
    }

    let helper_id = ($helper_ids | first | get id)
    let floors = ($BPF_HELPER_KERNEL_FLOORS_BY_MAX_ID | where {|floor| $helper_id <= $floor.max_id })
    if ($floors | is-empty) {
        return null
    }

    let floor = ($floors | first)
    let min_kernel = ($floor | get min_kernel)
    {
        key: $"helper:($name)"
        min_kernel: $min_kernel
        source: $"https://github.com/torvalds/linux/blob/v($min_kernel)/include/uapi/linux/bpf.h"
    }
}

def kfunc-kernel-feature [name: string] {
    let matches = ($KFUNC_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if not ($matches | is-empty) {
        return ($matches | first | get feature)
    }

    let fallback = ($KFUNC_KERNEL_FEATURE_FALLBACKS | where {|entry| $entry.name == $name })
    if ($fallback | is-empty) {
        return null
    }

    let entry = ($fallback | first)
    mut feature = {
        key: $"kfunc:($name)"
        min_kernel: ($entry | get min_kernel)
        source: ($entry | get source)
    }

    let max_kernel = ($entry | get -o max_kernel_exclusive)
    if $max_kernel != null and $max_kernel != "" {
        $feature = ($feature | insert max_kernel_exclusive $max_kernel)
        let max_kernel_source = ($entry | get -o max_kernel_exclusive_source)
        if $max_kernel_source != null and $max_kernel_source != "" {
            $feature = ($feature | insert max_kernel_exclusive_source $max_kernel_source)
        }
    }

    $feature
}
