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
    {
        name: "source-kfunc-sched-ext-select-cpu-scalars"
        category: "kfunc"
        tags: [kfunc sched-ext source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let p = $ctx.arg.p'
            '        let prev = $ctx.arg.prev_cpu'
            '        let now = (kfunc-call "scx_bpf_now")'
            '        let cpu_count = (kfunc-call "scx_bpf_nr_cpu_ids")'
            '        let node_count = (kfunc-call "scx_bpf_nr_node_ids")'
            '        let rq = (kfunc-call "scx_bpf_cpu_rq" $prev)'
            '        let cap = (kfunc-call "scx_bpf_cpuperf_cap" $prev)'
            '        let cur = (kfunc-call "scx_bpf_cpuperf_cur" $prev)'
            '        kfunc-call "scx_bpf_cpuperf_set" $prev $cur'
            '        kfunc-call "scx_bpf_kick_cpu" $prev 0'
            '        let was_idle = (kfunc-call "scx_bpf_test_and_clear_cpu_idle" $prev)'
            '        let task_cpu = (kfunc-call "scx_bpf_task_cpu" $p)'
            '        let running = (kfunc-call "scx_bpf_task_running" $p)'
            '        let cpu = ($now + $cpu_count + $node_count + $cap + $cur + $was_idle + $task_cpu + $running)'
            '        if $rq { $cpu } else { $cpu }'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-task-cgroup-release"
        category: "kfunc"
        tags: [kfunc sched-ext cgroup ref-lifetime source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let cgrp = (kfunc-call "scx_bpf_task_cgroup" $ctx.arg.p)'
            '        if $cgrp {'
            '            $cgrp | kfunc-call "bpf_cgroup_release"'
            '        }'
            '        $ctx.arg.prev_cpu'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-select-cpu-online-mask"
        category: "kfunc"
        tags: [kfunc sched-ext cpumask ref-lifetime source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let p = $ctx.arg.p'
            '        let prev = $ctx.arg.prev_cpu'
            '        let wake = $ctx.arg.wake_flags'
            '        let is_idle = "00"'
            '        let dfl = (kfunc-call "scx_bpf_select_cpu_dfl" $p $prev $wake $is_idle)'
            '        let mask = (kfunc-call "scx_bpf_get_online_cpumask")'
            '        if $mask {'
            '            let any = (kfunc-call "scx_bpf_pick_any_cpu" $mask 0)'
            '            let idle = (kfunc-call "scx_bpf_pick_idle_cpu" $mask 0)'
            '            let cpu = (kfunc-call "scx_bpf_select_cpu_and" $p $prev $wake $mask 0)'
            '            kfunc-call "scx_bpf_put_cpumask" $mask'
            '            ($cpu + $any + $idle)'
            '        } else {'
            '            $dfl'
            '        }'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-possible-mask"
        category: "kfunc"
        tags: [kfunc sched-ext cpumask ref-lifetime source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let prev = $ctx.arg.prev_cpu'
            '        let mask = (kfunc-call "scx_bpf_get_possible_cpumask")'
            '        if $mask {'
            '            let any = (kfunc-call "scx_bpf_pick_any_cpu_node" $mask 0 0)'
            '            kfunc-call "scx_bpf_put_cpumask" $mask'
            '            $any'
            '        } else {'
            '            $prev'
            '        }'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-pick-idle-cpu-node-requires-flag"
        category: "kfunc"
        tags: [kfunc sched-ext cpumask source reject]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let mask = (kfunc-call "scx_bpf_get_possible_cpumask")'
            '        if $mask {'
            '            let cpu = (kfunc-call "scx_bpf_pick_idle_cpu_node" $mask 0 0)'
            '            kfunc-call "scx_bpf_put_cpumask" $mask'
            '            $cpu'
            '        } else {'
            '            $ctx.arg.prev_cpu'
            '        }'
            '    }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "without SCX_OPS_BUILTIN_IDLE_PER_NODE"
    }
    {
        name: "source-kfunc-sched-ext-idle-masks"
        category: "kfunc"
        tags: [kfunc sched-ext cpumask ref-lifetime source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let prev = $ctx.arg.prev_cpu'
            '        let idle_mask = (kfunc-call "scx_bpf_get_idle_cpumask")'
            '        let idle_cpu = (if $idle_mask {'
            '            let cpu = (kfunc-call "scx_bpf_pick_idle_cpu" $idle_mask 0)'
            '            kfunc-call "scx_bpf_put_idle_cpumask" $idle_mask'
            '            $cpu'
            '        } else { 0 })'
            '        let idle_node = (kfunc-call "scx_bpf_get_idle_cpumask_node" 0)'
            '        if $idle_node {'
            '            kfunc-call "scx_bpf_put_idle_cpumask" $idle_node'
            '        }'
            '        let smt_mask = (kfunc-call "scx_bpf_get_idle_smtmask")'
            '        if $smt_mask {'
            '            kfunc-call "scx_bpf_put_idle_cpumask" $smt_mask'
            '        }'
            '        let smt_node = (kfunc-call "scx_bpf_get_idle_smtmask_node" 0)'
            '        if $smt_node {'
            '            kfunc-call "scx_bpf_put_idle_cpumask" $smt_node'
            '        }'
            '        ($prev + $idle_cpu)'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-task-cgroup-rejects-leak"
        category: "kfunc"
        tags: [kfunc sched-ext cgroup ref-lifetime source reject]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let cgrp = (kfunc-call "scx_bpf_task_cgroup" $ctx.arg.p)'
            '        $ctx.arg.prev_cpu'
            '    }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
]
