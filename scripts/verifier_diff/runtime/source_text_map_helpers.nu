def helper-call-tail-name [tail: string] {
    let raw_helper = ($tail | str trim | split row " " | first)
    normalize-helper-name-token $raw_helper
}

def source-line-helper-call-name [line: string] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    helper-call-tail-name ($tails | first)
}

def helper-call-map-kind-entry-for-helper [helper_name] {
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

def helper-call-map-kind-entry-for-tail [tail: string] {
    helper-call-map-kind-entry-for-helper (helper-call-tail-name $tail)
}

def helper-call-map-kind-entry [line: string] {
    helper-call-map-kind-entry-for-helper (source-line-helper-call-name $line)
}

def helper-call-tail-map-name [tail: string entry] {
    let tokens = (
        $tail
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

def source-line-helper-call-map-name [line: string entry] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    helper-call-tail-map-name ($tails | first) $entry
}

def helper-call-effective-map-kind-for-tail [tail: string bindings] {
    let entry = (helper-call-map-kind-entry-for-tail $tail)
    if $entry == null {
        return null
    }

    let fixed_kind = ($entry | get -o kind)
    if $fixed_kind != null and $fixed_kind != "" {
        return $fixed_kind
    }

    let supported_kinds = ($entry | get -o kinds | default [])
    let explicit_kind = (source-line-map-kind $tail "")
    if $explicit_kind != "" {
        if $explicit_kind in $supported_kinds {
            return $explicit_kind
        }
        return null
    }

    let map_name = (helper-call-tail-map-name $tail $entry)
    let inferred_kind = (map-kind-binding $bindings $map_name)
    if $inferred_kind != null and ($inferred_kind in $supported_kinds) {
        return $inferred_kind
    }

    null
}

def helper-call-effective-map-kind [line: string bindings] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    helper-call-effective-map-kind-for-tail ($tails | first) $bindings
}

def helper-call-map-kind-kernel-feature [line: string bindings] {
    let kind = (helper-call-effective-map-kind $line $bindings)
    if $kind == null or $kind == "" {
        return null
    }

    map-kind-kernel-feature $kind
}

def helper-call-map-kind-kernel-features [line: string bindings] {
    mut features = []

    for tail in (command-invocation-tails $line "helper-call") {
        let kind = (helper-call-effective-map-kind-for-tail $tail $bindings)
        if $kind == null or $kind == "" {
            continue
        }

        let feature = (map-kind-kernel-feature $kind)
        if $feature != null {
            $features = (append-missing-kernel-features $features [$feature])
        }
    }

    $features
}

def source-line-map-kind [line: string default_kind: string] {
    for raw_tail in (marker-tails-outside-simple-string $line "--kind ") {
        let raw_kind = ($raw_tail | str trim | split row " " | first)
        return (normalize-map-kind-token $raw_kind)
    }

    $default_kind
}

def map-kind-surface-commands [] {
    [
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
    ]
}

def source-line-command-map-name-from-tail [tail: string] {
    let raw_name = ($tail | str trim | split row " " | first)
    let name = (normalize-map-name-token $raw_name)
    if $name == "" or ($name | str starts-with "$") {
        null
    } else {
        $name
    }
}

def source-line-command-map-name [line: string command: string] {
    let tails = (command-invocation-tails $line $command)
    if ($tails | is-empty) {
        return null
    }

    source-line-command-map-name-from-tail ($tails | first)
}

def source-line-map-kind-surfaces [line: string] {
    mut surfaces = []

    for command in (map-kind-surface-commands) {
        for tail in (command-invocation-tails $line $command) {
            $surfaces = (
                $surfaces
                | append {
                    command: $command
                    name: (source-line-command-map-name-from-tail $tail)
                    tail: $tail
                }
            )
        }
    }

    $surfaces
}

def source-line-map-kind-surface [line: string] {
    let surfaces = (source-line-map-kind-surfaces $line)
    if ($surfaces | is-empty) {
        null
    } else {
        $surfaces | first
    }
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

def source-line-effective-map-kind-for-surface [surface bindings] {
    if $surface == null {
        return null
    }

    let explicit_kind = (source-line-map-kind ($surface | get tail) "")
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

def source-line-effective-map-kind [line: string bindings] {
    source-line-effective-map-kind-for-surface (source-line-map-kind-surface $line) $bindings
}

def map-kind-kernel-features-for-line [line: string bindings] {
    mut features = []
    mut updated = $bindings

    for surface in (source-line-map-kind-surfaces $line) {
        let kind = (source-line-effective-map-kind-for-surface $surface $updated)
        if $kind != null and $kind != "" {
            let feature = (map-kind-kernel-feature $kind)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
        $updated = (bind-map-kind $updated ($surface | get name) $kind)
    }

    $features
}

def update-map-kind-bindings-for-line [bindings line: string] {
    mut updated = $bindings

    for surface in (source-line-map-kind-surfaces $line) {
        let kind = (source-line-effective-map-kind-for-surface $surface $updated)
        $updated = (bind-map-kind $updated ($surface | get name) $kind)
    }

    $updated
}

def update-helper-call-map-kind-bindings-for-line [bindings line: string] {
    mut updated = $bindings

    for tail in (command-invocation-tails $line "helper-call") {
        let entry = (helper-call-map-kind-entry-for-tail $tail)
        if $entry == null {
            continue
        }

        let name = (helper-call-tail-map-name $tail $entry)
        let kind = (helper-call-effective-map-kind-for-tail $tail $updated)
        $updated = (bind-map-kind $updated $name $kind)
    }

    $updated
}

def line-invokes-map-kind-surface? [line: string] {
    for command in (map-kind-surface-commands) {
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
