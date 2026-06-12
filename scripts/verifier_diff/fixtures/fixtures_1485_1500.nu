const VERIFIER_DIFF_FIXTURES_1485_1500 = [
    {
        name: "source-kfunc-rcu-read-lock-unlock"
        category: "helper-state"
        tags: [kfunc rcu source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rcu-read-lock-user-function-unlock"
        category: "helper-state"
        tags: [kfunc rcu source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def lock [] {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '    0'
            '  }'
            '  def unlock [] {'
            '    kfunc-call "bpf_rcu_read_unlock"'
            '    0'
            '  }'
            '  lock'
            '  unlock'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-return-use"
        category: "helper-state"
        tags: [kfunc rcu source void-return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock" | count'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void kfunc 'bpf_rcu_read_lock' return value cannot be used"
    }
    {
        name: "source-kfunc-rcu-read-unlock-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_rcu_read_lock"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-leak"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased RCU read lock"
    }
    {
        name: "source-kfunc-rcu-read-unlock-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '  }'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_rcu_read_lock"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-branch-leak"
        category: "helper-state"
        tags: [kfunc rcu source branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '  } else {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '    kfunc-call "bpf_rcu_read_unlock"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased RCU read lock"
    }
    {
        name: "source-kfunc-preempt-disable-enable"
        category: "helper-state"
        tags: [kfunc preempt source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-preempt-disable-user-function-enable"
        category: "helper-state"
        tags: [kfunc preempt source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def disable [] {'
            '    kfunc-call "bpf_preempt_disable"'
            '    0'
            '  }'
            '  def enable [] {'
            '    kfunc-call "bpf_preempt_enable"'
            '    0'
            '  }'
            '  disable'
            '  enable'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-preempt-enable-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_preempt_disable"
    }
    {
        name: "source-kfunc-preempt-disable-rejects-leak"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased preempt disable"
    }
    {
        name: "source-kfunc-preempt-enable-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_preempt_disable"'
            '  }'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_preempt_disable"
    }
    {
        name: "source-kfunc-preempt-disable-rejects-branch-leak"
        category: "helper-state"
        tags: [kfunc preempt source branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_preempt_disable"'
            '  } else {'
            '    kfunc-call "bpf_preempt_disable"'
            '    kfunc-call "bpf_preempt_enable"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased preempt disable"
    }
    {
        name: "source-kfunc-local-irq-save-restore"
        category: "helper-state"
        tags: [kfunc irq source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-local-irq-user-function-save-restore"
        category: "helper-state"
        tags: [kfunc irq source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def save [flags] {'
            '    kfunc-call "bpf_local_irq_save" $flags'
            '    0'
            '  }'
            '  def restore [flags] {'
            '    kfunc-call "bpf_local_irq_restore" $flags'
            '    0'
            '  }'
            '  let flags = "00000000"'
            '  save $flags'
            '  restore $flags'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-local-irq-restore-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_local_irq_save"
    }
]
