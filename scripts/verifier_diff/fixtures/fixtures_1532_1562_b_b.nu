const VERIFIER_DIFF_FIXTURES_1532_1562_B_B = [
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
