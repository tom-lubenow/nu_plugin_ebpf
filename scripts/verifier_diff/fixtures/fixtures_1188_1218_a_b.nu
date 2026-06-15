const VERIFIER_DIFF_FIXTURES_1188_1218_A_B = [
    {
        name: "source-kfunc-iter-task-null-task-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_new" $iter 0 0'
            '  let task = (kfunc-call "bpf_iter_task_next" $iter)'
            '  if $task { 0 }'
            '  kfunc-call "bpf_iter_task_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-task-rejects-nonzero-task-scalar"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_new" $iter 1 0'
            '  kfunc-call "bpf_iter_task_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_task_new' arg1 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-iter-task-vma-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_vma_new" $iter $ctx.current_task 0'
            '  let vma = (kfunc-call "bpf_iter_task_vma_next" $iter)'
            '  if $vma { 0 }'
            '  kfunc-call "bpf_iter_task_vma_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-task-vma-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_vma_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_task_vma_next' requires a matching bpf_iter_task_vma_new"
    }
    {
        name: "source-kfunc-iter-task-vma-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_vma_new" $iter $ctx.current_task 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_task_vma iterator"
    }
]
