const VERIFIER_DIFF_FIXTURES_0469_0500_A = [
    {
        name: "source-helper-probe-read-user-str-accepts-user-src"
        category: "helper-state"
        tags: [helper probe-read user string accept source metadata]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "01234567"'
            '    helper-call "bpf_probe_read_user_str" $dst 8 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-user-rejects-stack-src"
        category: "helper-state"
        tags: [helper probe-read user reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  let src = "abcdefgh"'
            '  helper-call "bpf_probe_read_user" $dst 8 $src'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper probe_read src expects pointer in [User]"
    }
    {
        name: "source-helper-probe-read-rejects-xdp"
        category: "helper-state"
        tags: [helper probe-read program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read" $dst 8 $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_probe_read' is only valid"
    }
    {
        name: "source-helper-current-identity-and-clock-helpers"
        category: "helper-state"
        tags: [helper current time accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_current_pid_tgid"'
            '  helper-call "bpf_get_current_uid_gid"'
            '  helper-call "bpf_get_current_task"'
            '  helper-call "bpf_get_current_task_btf"'
            '  helper-call "bpf_get_smp_processor_id"'
            '  helper-call "bpf_get_numa_node_id"'
            '  helper-call "bpf_jiffies64"'
            '  helper-call "bpf_ktime_get_ns"'
            '  helper-call "bpf_ktime_get_boot_ns"'
            '  helper-call "bpf_ktime_get_tai_ns"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-current-comm-accepts-map-buffer"
        category: "helper-state"
        tags: [helper current comm map-bounds accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define comm_buf_ok --kind array --value-type bytes:16 --max-entries 1'
            '  let dst = (0 | map-get comm_buf_ok)'
            '  if $dst {'
            '    helper-call "bpf_get_current_comm" $dst 16'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-current-comm-rejects-short-map-buffer"
        category: "helper-state"
        tags: [helper current comm map-bounds reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define comm_buf_short --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get comm_buf_short)'
            '  if $dst {'
            '    helper-call "bpf_get_current_comm" $dst 16'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_current_comm dst requires 16 bytes"
    }
    {
        name: "source-helper-get-current-comm-rejects-dynamic-short-map-buffer"
        category: "helper-state"
        tags: [helper current comm map-bounds dynamic reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define comm_buf_dyn_short --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get comm_buf_dyn_short)'
            '  if $dst {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_get_current_comm" $dst $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_current_comm dst requires 16 bytes"
    }
]
