def callback-trusted-btf-param-indexes [helper_name: string] {
    if $helper_name in ["bpf_timer_set_callback" "bpf_for_each_map_elem"] {
        return [0]
    }
    if $helper_name == "bpf_find_vma" {
        return [0 1]
    }

    []
}

def helper-call-name-from-line [line: string] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    normalize-helper-name-token (($tails | first | str trim | split row " " | first))
}

def closure-param-names-from-line [line: string] {
    let closure_parts = ($line | split row "{|")
    if ($closure_parts | length) <= 1 {
        return []
    }

    let raw_closure = ($closure_parts | skip 1 | first)
    let param_parts = ($raw_closure | split row "|")
    if ($param_parts | length) == 0 {
        return []
    }

    $param_parts
    | first
    | str replace --all "," " "
    | split row " "
    | each {|param| $param | str trim }
    | where {|param| $param != "" }
}

def helper-call-trusted-btf-callback-roots [line: string] {
    let helper_name = (helper-call-name-from-line $line)
    if $helper_name == null {
        return []
    }

    let trusted_indexes = (callback-trusted-btf-param-indexes $helper_name)
    if ($trusted_indexes | is-empty) {
        return []
    }

    let params = (closure-param-names-from-line $line)
    if ($params | is-empty) {
        return []
    }

    mut roots = []
    for idx in $trusted_indexes {
        if $idx < ($params | length) {
            let param = ($params | get $idx)
            if $param not-in $roots {
                $roots = ($roots | append $param)
            }
        }
    }

    $roots
}

def program-callback-btf-kernel-features [source: string] {
    mut features = []
    mut trusted_roots = []

    for line in ($source | lines) {
        let callback_roots = (helper-call-trusted-btf-callback-roots $line)
        if not ($callback_roots | is-empty) {
            $trusted_roots = $callback_roots
        }

        for root in $trusted_roots {
            let prefix = $"$($root)."
            let parts = ($line | split row $prefix)
            if ($parts | length) <= 1 {
                continue
            }

            for raw_tail in ($parts | skip 1) {
                let field = (normalize-context-field-token $raw_tail)
                if $field != "" {
                    # Trusted-BTF callback scalar projections lower as direct
                    # loads, not probe_read_kernel helper calls.
                    continue
                }
            }
        }

        let trimmed = ($line | str trim)
        if not ($trusted_roots | is-empty) and ($trimmed | str starts-with "}") {
            $trusted_roots = []
        }
    }

    $features
}
