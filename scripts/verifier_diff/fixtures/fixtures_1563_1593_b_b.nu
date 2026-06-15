const VERIFIER_DIFF_FIXTURES_1563_1593_B_B = [
    {
        name: "seq-write-iter-meta"
        category: "helper-state"
        tags: [iter helper-call seq]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_seq_write" $ctx.meta.seq $data 4'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "seq-write-rejects-non-iter"
        category: "helper-state"
        tags: [raw-tracepoint helper-call seq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_seq_write" 0 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_seq_write' is only valid in iter programs"
    }
    {
        name: "seq-printf-allows-null-zero-data"
        category: "helper-state"
        tags: [iter helper-call seq]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let fmt = "value\u{0}"'
            '  let btf_ptr = "0123456789abcdef"'
            '  helper-call "bpf_seq_printf" $ctx.meta.seq $fmt 6 0 0'
            '  helper-call "bpf_seq_printf_btf" $ctx.meta.seq $btf_ptr 16 15'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "seq-printf-rejects-unaligned-data-len"
        category: "helper-state"
        tags: [iter helper-call seq reject]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let fmt = "value\u{0}"'
            '  let data = "01234567"'
            '  helper-call "bpf_seq_printf" $ctx.meta.seq $fmt 6 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_seq_printf' requires arg4 to be a multiple of 8"
    }
    {
        name: "seq-printf-rejects-dynamic-unaligned-data-len"
        category: "helper-state"
        tags: [iter helper-call seq dynamic branch reject]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let fmt = "value\u{0}"'
            '  let data = "01234567"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let data_len = (if $selector == 0 { 8 } else { 4 })'
            '  helper-call "bpf_seq_printf" $ctx.meta.seq $fmt 6 $data $data_len'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_seq_printf' requires arg4 to be a multiple of 8"
    }
    {
        name: "callback-bpf-loop"
        category: "callbacks"
        tags: [helper-call callback bpf-loop]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb|'
            '    $i | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-bpf-loop-record-context"
        category: "callbacks"
        tags: [helper-call callback bpf-loop record]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb|'
            '    $cb.count | count'
            '    0'
            '  } { count: 9 } 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
