const VERIFIER_DIFF_FIXTURES_0469_0500_A_B = [
    {
        name: "xdp-ktime-get-coarse-helper"
        category: "helper-state"
        tags: [helper time accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ktime_get_coarse_ns"'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-ktime-get-coarse-rejects-raw-tracepoint"
        category: "helper-state"
        tags: [helper time program-policy reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ktime_get_coarse_ns"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ktime_get_coarse_ns' is only valid"
    }
    {
        name: "source-helper-current-cgroup-namespace-helpers"
        category: "helper-state"
        tags: [helper current cgroup namespace accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_ok --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata_ok)'
            '  helper-call "bpf_get_current_cgroup_id"'
            '  helper-call "bpf_get_current_ancestor_cgroup_id" 0'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-ns-current-pid-tgid-rejects-short-map-buffer"
        category: "helper-state"
        tags: [helper current namespace map-bounds reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_short --kind array --value-type bytes:4 --max-entries 1'
            '  let ns = (0 | map-get nsdata_short)'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_ns_current_pid_tgid nsdata requires 8 bytes"
    }
    {
        name: "source-helper-get-ns-current-pid-tgid-rejects-dynamic-short-map-buffer"
        category: "helper-state"
        tags: [helper current namespace map-bounds dynamic reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_dyn_short --kind array --value-type bytes:4 --max-entries 1'
            '  let ns = (0 | map-get nsdata_dyn_short)'
            '  if $ns {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 4 } else { 8 })'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_ns_current_pid_tgid nsdata requires 8 bytes"
    }
    {
        name: "source-helper-get-ns-current-pid-tgid-rejects-invalid-size"
        category: "helper-state"
        tags: [helper current namespace size reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_ok --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata_ok)'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_ns_current_pid_tgid' requires arg3 = 8"
    }
    {
        name: "source-helper-get-ns-current-pid-tgid-rejects-dynamic-size"
        category: "helper-state"
        tags: [helper current namespace size dynamic reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_dynamic --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata_dynamic)'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_ns_current_pid_tgid' requires arg3 = 8"
    }
    {
        name: "source-helper-tracing-context-cookie-helpers"
        category: "helper-state"
        tags: [helper tracing context-cookie accept source metadata]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_func_ip" $ctx'
            '  helper-call "bpf_get_attach_cookie" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-tracing-context-cookie-rejects-xdp"
        category: "helper-state"
        tags: [helper tracing context-cookie program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_func_ip" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_func_ip' is only valid"
    }
]
