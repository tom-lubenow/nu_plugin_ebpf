const VERIFIER_DIFF_FIXTURES_1501_1531 = [
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
    {
        name: "source-kfunc-sched-ext-compat-window"
        category: "kfunc"
        tags: [kfunc sched-ext source metadata compat-window]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    cpu_release: {|ctx|'
            '        let ignored = (kfunc-call "scx_bpf_reenqueue_local")'
            '        0'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-init-dsq"
        category: "kfunc"
        tags: [kfunc sched-ext dsq source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    init: {|ctx|'
            '        let err = (kfunc-call "scx_bpf_create_dsq" 1 0)'
            '        if $err == 0 {'
            '            kfunc-call "scx_bpf_destroy_dsq" 1'
            '        }'
            '        0'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-dispatch-core"
        category: "kfunc"
        tags: [kfunc sched-ext dispatch dsq source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    dispatch: {|ctx|'
            '        let slots = (kfunc-call "scx_bpf_dispatch_nr_slots")'
            '        if $slots {'
            '            kfunc-call "scx_bpf_dispatch_cancel"'
            '        }'
            '        let moved = (kfunc-call "scx_bpf_dsq_move_to_local" 0)'
            '        let queued = (kfunc-call "scx_bpf_dsq_nr_queued" 0)'
            '        if ($moved + $queued) { 0 } else { 0 }'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-enqueue-dsq-insert"
        category: "kfunc"
        tags: [kfunc sched-ext dsq source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    enqueue: {|ctx|'
            '        let p = $ctx.arg.p'
            '        kfunc-call "scx_bpf_dsq_insert" $p 0 0 0'
            '        kfunc-call "scx_bpf_dsq_insert_vtime" $p 0 0 0 0'
            '        0'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-bstr-events"
        category: "kfunc"
        tags: [kfunc sched-ext bstr events source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    init: {|ctx|'
            '        let events = "00000000"'
            '        let fmt = "0"'
            '        let data = "00000000"'
            '        kfunc-call "scx_bpf_events" $events 4'
            '        kfunc-call "scx_bpf_dump_bstr" $fmt $data 4'
            '        kfunc-call "scx_bpf_error_bstr" $fmt $data 4'
            '        kfunc-call "scx_bpf_exit_bstr" 0 $fmt $data 4'
            '        0'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-events-rejects-zero-size"
        category: "kfunc"
        tags: [kfunc sched-ext events source reject]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    init: {|ctx|'
            '        let events = "00000000"'
            '        kfunc-call "scx_bpf_events" $events 0'
            '        0'
            '    }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'scx_bpf_events' arg1 must be > 0"
    }
    {
        name: "source-kfunc-sched-ext-dsq-iter-move"
        category: "kfunc"
        tags: [kfunc sched-ext dsq iter ref-lifetime source accept]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    dispatch: {|ctx|'
            '        let iter = "0123456789abcdef0123456789abcdef"'
            '        kfunc-call "bpf_iter_scx_dsq_new" $iter 0 0'
            '        let next = (kfunc-call "bpf_iter_scx_dsq_next" $iter)'
            '        kfunc-call "scx_bpf_dsq_move_set_slice" $iter 1'
            '        kfunc-call "scx_bpf_dsq_move_set_vtime" $iter 1'
            '        let task = (kfunc-call "bpf_task_from_pid" 1)'
            '        let moved = (if $task {'
            '            let plain = (kfunc-call "scx_bpf_dsq_move" $iter $task 0 0)'
            '            let vtime = (kfunc-call "scx_bpf_dsq_move_vtime" $iter $task 0 0)'
            '            kfunc-call "bpf_task_release" $task'
            '            ($plain + $vtime)'
            '        } else { 0 })'
            '        kfunc-call "bpf_iter_scx_dsq_destroy" $iter'
            '        if $next { $moved } else { $moved }'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-dsq-move-rejects-missing-iter"
        category: "kfunc"
        tags: [kfunc sched-ext dsq iter source reject]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    dispatch: {|ctx|'
            '        let iter = "0123456789abcdef0123456789abcdef"'
            '        kfunc-call "scx_bpf_dsq_move_set_slice" $iter 1'
            '        0'
            '    }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'scx_bpf_dsq_move_set_slice' requires a matching bpf_iter_scx_dsq_new"
    }
    {
        name: "source-kfunc-sched-ext-dsq-insert-v2"
        category: "kfunc"
        tags: [kfunc sched-ext dsq source accept compat-window]
        requires: [kernel-btf-kfunc:scx_bpf_dsq_insert___v2]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    enqueue: {|ctx|'
            '        let inserted = (kfunc-call "scx_bpf_dsq_insert___v2" $ctx.arg.p 0 0 0)'
            '        if $inserted { 0 } else { 0 }'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-reenqueue-local-v2"
        category: "kfunc"
        tags: [kfunc sched-ext dsq source accept compat-window]
        requires: [kernel-btf-kfunc:scx_bpf_reenqueue_local___v2]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    dispatch: {|ctx|'
            '        kfunc-call "scx_bpf_reenqueue_local___v2"'
            '        0'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "struct-ops-callback-target-rejects-attach"
        category: "program-model"
        tags: [struct-ops callback attach reject]
        target: "struct_ops:sched_ext_ops.select_cpu"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "struct_ops attach expects an object value type"
    }
    {
        name: "struct-ops-tcp-congestion-target-metadata"
        category: "program-model"
        tags: [struct-ops tcp-congestion metadata]
        target: "struct_ops:tcp_congestion_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    ssthresh: {|ctx| 2 }'
            '    cong_avoid: {|ctx| 0 }'
            '    undo_cwnd: {|ctx| 2 }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "raw-tcp-send-ack-helper"
        category: "helper-state"
        tags: [helper-call tcp struct-ops tcp-congestion accept source metadata]
        target: "struct_ops:tcp_congestion_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    ssthresh: {|ctx| 2 }'
            '    cong_avoid: {|ctx|'
            '        helper-call "bpf_tcp_send_ack" $ctx.arg0 0'
            '        0'
            '    }'
            '    undo_cwnd: {|ctx| 2 }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "struct-ops-sleepable-callback-target-metadata"
        category: "program-model"
        tags: [struct-ops callback sleepable metadata attach reject]
        target: "struct_ops:sched_ext_ops.init"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "struct_ops attach expects an object value type"
    }
    {
        name: "struct-ops-object-sleepable-callback-source-metadata"
        category: "program-model"
        tags: [struct-ops callback sleepable source metadata]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    init: {|ctx|'
            '        0'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "timer-init-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_init" 0 timers 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-init-rejects-dynamic-non-map-timer"
        category: "helper-state"
        tags: [timer dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_dyn_init --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers_dyn_init --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let timer = (if $selector == 0 { $entry.timer } else { 0 })'
            '    helper-call "bpf_timer_init" $timer timers_dyn_init 0 --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
]
