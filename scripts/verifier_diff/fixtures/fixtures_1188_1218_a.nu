const VERIFIER_DIFF_FIXTURES_1188_1218_A = [
    {
        name: "source-kfunc-iter-num-accepts-reinit-after-conditional-balanced-lifecycle"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_num_new" $iter 0 4'
            '    kfunc-call "bpf_iter_num_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_num_new" $iter 4 8'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-num-rejects-wrong-family-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_bits_destroy' requires a matching bpf_iter_bits_new"
    }
    {
        name: "source-kfunc-iter-num-rejects-conditional-destroy-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_num_destroy" $iter'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_num iterator"
    }
    {
        name: "source-kfunc-iter-num-rejects-destroy-after-conditional-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_num_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_num_destroy' requires a matching bpf_iter_num_new"
    }
    {
        name: "source-kfunc-iter-bits-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  let item = (kfunc-call "bpf_iter_bits_next" $iter)'
            '  if $item { 0 }'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-bits-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_bits_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_bits_next' requires a matching bpf_iter_bits_new"
    }
    {
        name: "source-kfunc-iter-bits-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_bits iterator"
    }
    {
        name: "source-kfunc-iter-bits-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_bits_destroy' requires a matching bpf_iter_bits_new"
    }
    {
        name: "source-kfunc-iter-bits-rejects-reinit-after-conditional-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  }'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_bits stack object slot"
    }
    {
        name: "source-kfunc-iter-bits-accepts-reinit-after-conditional-balanced-lifecycle"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '    kfunc-call "bpf_iter_bits_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
