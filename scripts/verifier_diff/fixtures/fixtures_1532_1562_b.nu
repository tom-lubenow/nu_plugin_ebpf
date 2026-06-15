const VERIFIER_DIFF_FIXTURES_1532_1562_B = [
    {
        name: "timer-cancel-rejects-dynamic-non-map-timer"
        category: "helper-state"
        tags: [timer dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_dyn_cancel --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers_dyn_cancel --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let timer = (if $selector == 0 { $entry.timer } else { 0 })'
            '    helper-call "bpf_timer_cancel" $timer'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "ringbuf-query-rejects-invalid-flags"
        category: "helper-state"
        tags: [ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" events 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_query' requires arg1 flags"
    }
    {
        name: "ringbuf-query-rejects-dynamic-flags"
        category: "helper-state"
        tags: [ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_ringbuf_query" events $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_query' requires arg1 flags"
    }
    {
        name: "bpf-loop-rejects-invalid-flags"
        category: "helper-state"
        tags: [bpf-loop flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb| 0 } "ctx" 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg3 flags to be 0"
    }
    {
        name: "bpf-loop-rejects-dynamic-flags"
        category: "helper-state"
        tags: [bpf-loop flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_loop" 4 {|i cb| 0 } "ctx" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg3 flags to be 0"
    }
    {
        name: "bpf-loop-rejects-too-many-iterations"
        category: "helper-state"
        tags: [bpf-loop bounds reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 8388609 {|i cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg0 nr_loops"
    }
    {
        name: "bpf-loop-rejects-dynamic-too-many-iterations"
        category: "helper-state"
        tags: [bpf-loop bounds dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let loops = ((helper-call "bpf_get_prandom_u32") + 8388609)'
            '  helper-call "bpf_loop" $loops {|i cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg0 nr_loops"
    }
    {
        name: "user-ringbuf-drain-rejects-invalid-flags"
        category: "helper-state"
        tags: [user-ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_user_ringbuf_drain' requires arg3 flags"
    }
    {
        name: "user-ringbuf-drain-rejects-dynamic-flags"
        category: "helper-state"
        tags: [user-ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_user_ringbuf_drain' requires arg3 flags"
    }
]
