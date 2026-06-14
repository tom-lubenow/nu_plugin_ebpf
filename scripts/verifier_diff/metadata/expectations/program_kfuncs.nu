const PROGRAM_KFUNC_RAW_TRACEPOINT_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let text = "kfunc-call \"bpf_task_from_pid\" 1"'
            '  # kfunc-call "bpf_task_from_pid" 1'
            '  let ignored = 0 # | kfunc-call "bpf_task_from_pid" 1'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_rcu_read_lock" "kfunc:bpf_rcu_read_unlock"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_preempt_disable" "kfunc:bpf_preempt_enable"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_local_irq_save" "kfunc:bpf_local_irq_restore"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_lock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_unlock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        feature_keys: [
            "kfunc:bpf_res_spin_lock"
            "kfunc:bpf_res_spin_unlock"
            "kfunc:bpf_res_spin_lock_irqsave"
            "kfunc:bpf_res_spin_unlock_irqrestore"
        ]
    }
]

let PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS = (
    $PROGRAM_KFUNC_RAW_TRACEPOINT_KERNEL_FEATURE_EXPECTATIONS
    | append $PROGRAM_KFUNC_SOCK_ADDR_KERNEL_FEATURE_EXPECTATIONS
)
