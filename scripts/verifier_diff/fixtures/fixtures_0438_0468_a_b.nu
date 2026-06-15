const VERIFIER_DIFF_FIXTURES_0438_0468_A_B = [
    {
        name: "dynptr-from-mem-rejects-reinit-after-one-branch-initialization"
        category: "helper-state"
        tags: [dynptr phi reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_reinit_join_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_reinit_join_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    }'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' arg3 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-read-write-initialized-from-mem"
        category: "helper-state"
        tags: [dynptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_rw_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_rw_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    let src = "wxyz"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-read-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let out = "0000"'
            '  helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' arg2 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-read-rejects-nonzero-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_read_flag_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_read_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' requires arg4 flags to be 0"
    }
    {
        name: "dynptr-read-rejects-dynamic-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_read_dynamic_flag_buffers 0 --kind array'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get dynptr_read_dynamic_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' requires arg4 flags to be 0"
    }
    {
        name: "dynptr-read-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [dynptr ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let out = "0000"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' arg2 ringbuf dynptr reservation already released"
    }
    {
        name: "dynptr-write-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let src = "wxyz"'
            '  helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' arg0 requires initialized dynptr stack object"
    }
]
