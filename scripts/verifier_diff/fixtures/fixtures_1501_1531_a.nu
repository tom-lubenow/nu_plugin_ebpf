const VERIFIER_DIFF_FIXTURES_1501_1531_A = [
    {
        name: "source-kfunc-local-irq-save-rejects-leak"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased local irq disable"
    }
    {
        name: "source-kfunc-local-irq-restore-rejects-slot-mismatch"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let saved_flags = "00000000"'
            '  let other_flags = "11111111"'
            '  kfunc-call "bpf_local_irq_save" $saved_flags'
            '  kfunc-call "bpf_local_irq_restore" $other_flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_local_irq_save"
    }
    {
        name: "source-kfunc-local-irq-restore-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_local_irq_save" $flags'
            '  }'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_local_irq_save"
    }
    {
        name: "source-kfunc-local-irq-save-rejects-branch-leak"
        category: "helper-state"
        tags: [kfunc irq source branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_local_irq_save" $flags'
            '  } else {'
            '    kfunc-call "bpf_local_irq_save" $flags'
            '    kfunc-call "bpf_local_irq_restore" $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased local irq disable"
    }
    {
        name: "source-kfunc-res-spin-rejects-non-lock-kernel-pointer"
        category: "helper-state"
        tags: [kfunc res-spin-lock source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_res_spin_lock" $ctx.current_task'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_res_spin_lock pointer"
    }
    {
        name: "source-kfunc-res-spin-unlock-rejects-non-lock-kernel-pointer"
        category: "helper-state"
        tags: [kfunc res-spin-lock source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_res_spin_unlock" $ctx.current_task'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_res_spin_lock pointer"
    }
    {
        name: "source-kfunc-res-spin-irqsave-rejects-non-lock-kernel-pointer"
        category: "helper-state"
        tags: [kfunc res-spin-lock irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_res_spin_lock pointer"
    }
    {
        name: "source-kfunc-res-spin-irqrestore-rejects-non-lock-kernel-pointer"
        category: "helper-state"
        tags: [kfunc res-spin-lock irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_res_spin_lock pointer"
    }
    {
        name: "source-kfunc-sched-ext-node-min-kernel"
        category: "kfunc"
        tags: [kfunc sched-ext source metadata]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let prev = $ctx.arg.prev_cpu'
            '        kfunc-call "scx_bpf_cpu_node" $prev'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
