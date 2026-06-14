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
    {
        name: "trace-vprintk-accepts-stack-format-and-data"
        category: "helper-state"
        tags: [helper-call trace-vprintk accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  helper-call "bpf_trace_vprintk" $fmt 9 $data 16'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "trace-vprintk-rejects-zero-format-size"
        category: "helper-state"
        tags: [helper-call trace-vprintk scalar-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  helper-call "bpf_trace_vprintk" $fmt 0 $data 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 177 arg1 must be > 0"
    }
    {
        name: "trace-vprintk-rejects-dynamic-format-size"
        category: "helper-state"
        tags: [helper-call trace-vprintk scalar-policy dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_trace_vprintk" $fmt $size $data 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 177 arg1 must be > 0"
    }
    {
        name: "trace-vprintk-rejects-small-data-buffer"
        category: "helper-state"
        tags: [helper-call trace-vprintk bounds reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  map-define trace_vprintk_data --kind array --value-type bytes:8 --max-entries 1'
            '  let data = (0 | map-get trace_vprintk_data)'
            '  if $data { helper-call "bpf_trace_vprintk" $fmt 9 $data 16 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper trace_vprintk data"
    }
    {
        name: "trace-vprintk-rejects-unaligned-data-len"
        category: "helper-state"
        tags: [helper-call trace-vprintk scalar-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  helper-call "bpf_trace_vprintk" $fmt 9 $data 10'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_trace_vprintk' requires arg3 to be a multiple of 8"
    }
    {
        name: "trace-vprintk-rejects-dynamic-unaligned-data-len"
        category: "helper-state"
        tags: [helper-call trace-vprintk scalar-policy dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let data_len = (if $selector == 0 { 8 } else { 10 })'
            '  helper-call "bpf_trace_vprintk" $fmt 9 $data $data_len'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_trace_vprintk' requires arg3 to be a multiple of 8"
    }
    {
        name: "snprintf-btf-accepts-stack-btf-ptr"
        category: "helper-state"
        tags: [helper-call snprintf-btf accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 16 15'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
