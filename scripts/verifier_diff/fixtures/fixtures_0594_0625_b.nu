const VERIFIER_DIFF_FIXTURES_0594_0625_B = [
    {
        name: "dynptr-kfunc-clone-rejects-destination-initialized-on-one-path"
        category: "helper-state"
        tags: [kfunc dynptr branch reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let src = "0123456789abcdef"'
            '  let dst = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $src'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  }'
            '  kfunc-call "bpf_dynptr_clone" $src $dst'
            '  helper-call "bpf_ringbuf_discard_dynptr" $src 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg1 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-clone-submit-through-clone-balanced"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $clone 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-clone-submit-through-clone-invalidates-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $clone 0'
            '  kfunc-call "bpf_dynptr_size" $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-discard-invalidates-clone"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  kfunc-call "bpf_dynptr_size" $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-rejects-uninitialized-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  kfunc-call "bpf_dynptr_size" $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
]
