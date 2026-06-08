const VERIFIER_DIFF_FIXTURES_1501_1625 = [
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
    {
        name: "spin-lock-map-define-lock-unlock"
        category: "helper-state"
        tags: [spin-lock map-define accept]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "spin-lock-rejects-unreleased"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased bpf spin lock"
    }
    {
        name: "spin-lock-rejects-double-lock"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-rejects-unlock-of-different-map-entry"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let first = (0 | map-get locks --kind hash)'
            '  let second = (1 | map-get locks --kind hash)'
            '  if $first {'
            '    if $second {'
            '      helper-call "bpf_spin_lock" $first.lock'
            '      helper-call "bpf_spin_unlock" $second.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_spin_lock"
    }
    {
        name: "spin-lock-rejects-unlock-after-mixed-join"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '    }'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_spin_lock"
    }
    {
        name: "spin-lock-rejects-helper-while-held"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_get_prandom_u32"'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-rejects-kfunc-while-held"
        category: "helper-state"
        tags: [spin-lock map-define kfunc reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-rejects-throw-while-held"
        category: "helper-state"
        tags: [spin-lock map-define kfunc throw reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    kfunc-call "bpf_throw" 1'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_throw' cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-map-define-rejects-lru-hash"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define locks --kind lru-hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bpf_spin_lock, which is only supported for hash and array maps"
    }
    {
        name: "spin-lock-map-define-rejects-array-field"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{locks:array{bpf_spin_lock:2},counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_spin_lock"
    }
    {
        name: "timer-set-callback-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_set_callback" 0 {|timer key val| 0}'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-set-callback-rejects-dynamic-non-map-timer"
        category: "helper-state"
        tags: [timer callback dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_dyn_set --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers_dyn_set --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let timer = (if $selector == 0 { $entry.timer } else { 0 })'
            '    helper-call "bpf_timer_set_callback" $timer {|timer key val| 0}'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-start-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{||'
            '  helper-call "bpf_timer_start" 0 1000 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-start-rejects-dynamic-non-map-timer"
        category: "helper-state"
        tags: [timer dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_dyn_start --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers_dyn_start --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let timer = (if $selector == 0 { $entry.timer } else { 0 })'
            '    helper-call "bpf_timer_start" $timer 1000 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-cancel-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_cancel" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-cancel-rejects-dynamic-non-map-timer"
        category: "helper-state"
        tags: [timer dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_dyn_cancel --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers_dyn_cancel --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let timer = (if $selector == 0 { $entry.timer } else { 0 })'
            '    helper-call "bpf_timer_cancel" $timer'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "ringbuf-query-rejects-invalid-flags"
        category: "helper-state"
        tags: [ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" events 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_query' requires arg1 flags"
    }
    {
        name: "ringbuf-query-rejects-dynamic-flags"
        category: "helper-state"
        tags: [ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_ringbuf_query" events $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_query' requires arg1 flags"
    }
    {
        name: "bpf-loop-rejects-invalid-flags"
        category: "helper-state"
        tags: [bpf-loop flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb| 0 } "ctx" 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg3 flags to be 0"
    }
    {
        name: "bpf-loop-rejects-dynamic-flags"
        category: "helper-state"
        tags: [bpf-loop flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_loop" 4 {|i cb| 0 } "ctx" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg3 flags to be 0"
    }
    {
        name: "bpf-loop-rejects-too-many-iterations"
        category: "helper-state"
        tags: [bpf-loop bounds reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 8388609 {|i cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg0 nr_loops"
    }
    {
        name: "bpf-loop-rejects-dynamic-too-many-iterations"
        category: "helper-state"
        tags: [bpf-loop bounds dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let loops = ((helper-call "bpf_get_prandom_u32") + 8388609)'
            '  helper-call "bpf_loop" $loops {|i cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg0 nr_loops"
    }
    {
        name: "user-ringbuf-drain-rejects-invalid-flags"
        category: "helper-state"
        tags: [user-ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_user_ringbuf_drain' requires arg3 flags"
    }
    {
        name: "user-ringbuf-drain-rejects-dynamic-flags"
        category: "helper-state"
        tags: [user-ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_user_ringbuf_drain' requires arg3 flags"
    }
    {
        name: "trace-vprintk-accepts-stack-format-and-data"
        category: "helper-state"
        tags: [helper-call trace-vprintk accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  helper-call "bpf_trace_vprintk" $fmt 9 $data 16'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "trace-vprintk-rejects-zero-format-size"
        category: "helper-state"
        tags: [helper-call trace-vprintk scalar-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  helper-call "bpf_trace_vprintk" $fmt 0 $data 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 177 arg1 must be > 0"
    }
    {
        name: "trace-vprintk-rejects-dynamic-format-size"
        category: "helper-state"
        tags: [helper-call trace-vprintk scalar-policy dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_trace_vprintk" $fmt $size $data 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 177 arg1 must be > 0"
    }
    {
        name: "trace-vprintk-rejects-small-data-buffer"
        category: "helper-state"
        tags: [helper-call trace-vprintk bounds reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  map-define trace_vprintk_data --kind array --value-type bytes:8 --max-entries 1'
            '  let data = (0 | map-get trace_vprintk_data)'
            '  if $data { helper-call "bpf_trace_vprintk" $fmt 9 $data 16 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper trace_vprintk data"
    }
    {
        name: "trace-vprintk-rejects-unaligned-data-len"
        category: "helper-state"
        tags: [helper-call trace-vprintk scalar-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  helper-call "bpf_trace_vprintk" $fmt 9 $data 10'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_trace_vprintk' requires arg3 to be a multiple of 8"
    }
    {
        name: "trace-vprintk-rejects-dynamic-unaligned-data-len"
        category: "helper-state"
        tags: [helper-call trace-vprintk scalar-policy dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let data_len = (if $selector == 0 { 8 } else { 10 })'
            '  helper-call "bpf_trace_vprintk" $fmt 9 $data $data_len'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_trace_vprintk' requires arg3 to be a multiple of 8"
    }
    {
        name: "snprintf-btf-accepts-stack-btf-ptr"
        category: "helper-state"
        tags: [helper-call snprintf-btf accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 16 15'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "snprintf-accepts-map-format-and-stack-data"
        category: "helper-state"
        tags: [helper-call snprintf accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  map-define snprintf_fmt --kind array --value-type bytes:9 --max-entries 1'
            '  let fmt = (0 | map-get snprintf_fmt)'
            '  let data = "0123456789abcdef"'
            '  if $fmt { helper-call "bpf_snprintf" $out 32 $fmt $data 16 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "snprintf-rejects-extra-format-size-arg"
        category: "helper-state"
        tags: [helper-call snprintf reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  helper-call "bpf_snprintf" $out 32 $fmt 9 $data 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "BPF helper calls support at most 5 arguments"
    }
    {
        name: "snprintf-btf-rejects-negative-output-size"
        category: "helper-state"
        tags: [helper-call snprintf-btf scalar-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  let size = (0 - 1)'
            '  helper-call "bpf_snprintf_btf" $out $size $btf_ptr 16 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 149 arg1 must be > 0"
    }
    {
        name: "snprintf-btf-rejects-dynamic-negative-output-size"
        category: "helper-state"
        tags: [helper-call snprintf-btf scalar-policy dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  let size = (0 - (helper-call "bpf_get_prandom_u32"))'
            '  helper-call "bpf_snprintf_btf" $out $size $btf_ptr 16 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 149 arg1 must be > 0"
    }
    {
        name: "snprintf-btf-rejects-bad-btf-ptr-size"
        category: "helper-state"
        tags: [helper-call snprintf-btf scalar-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 8 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_snprintf_btf' requires arg3 = 16"
    }
    {
        name: "snprintf-btf-rejects-dynamic-btf-ptr-size"
        category: "helper-state"
        tags: [helper-call snprintf-btf scalar-policy dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  let btf_size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr $btf_size 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_snprintf_btf' requires arg3 = 16"
    }
    {
        name: "snprintf-btf-rejects-invalid-flags"
        category: "helper-state"
        tags: [helper-call snprintf-btf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 16 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_snprintf_btf' requires arg4 to contain only BTF_F_* bits"
    }
    {
        name: "snprintf-btf-rejects-dynamic-flags"
        category: "helper-state"
        tags: [helper-call snprintf-btf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 16 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_snprintf_btf' requires arg4 to contain only BTF_F_* bits"
    }
    {
        name: "snprintf-btf-rejects-small-btf-ptr-buffer"
        category: "helper-state"
        tags: [helper-call snprintf-btf bounds reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  map-define snprintf_btf_ptr --kind array --value-type bytes:8 --max-entries 1'
            '  let btf_ptr = (0 | map-get snprintf_btf_ptr)'
            '  if $btf_ptr { helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 16 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper snprintf_btf ptr"
    }
    {
        name: "perf-event-read-helpers"
        category: "helper-state"
        tags: [perf-event helper-call]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let value = "012345678901234567890123"'
            '  helper-call "bpf_perf_event_read" perf_events 0'
            '  helper-call "bpf_perf_event_read_value" perf_events 0 $value 24'
            '  helper-call "bpf_perf_prog_read_value" $ctx $value 24'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "perf-event-read-rejects-invalid-flags"
        category: "helper-state"
        tags: [perf-event flags reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  helper-call "bpf_perf_event_read" perf_events 4294967296'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "perf event read helpers require arg1 flags to fit BPF_F_INDEX_MASK/BPF_F_CURRENT_CPU"
    }
    {
        name: "perf-event-read-rejects-dynamic-out-of-range-flags"
        category: "helper-state"
        tags: [perf-event flags dynamic reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let flags = ((helper-call "bpf_get_prandom_u32") + 4294967296)'
            '  helper-call "bpf_perf_event_read" perf_events $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "perf event read helpers require arg1 flags to fit BPF_F_INDEX_MASK/BPF_F_CURRENT_CPU"
    }
    {
        name: "perf-event-read-value-rejects-size"
        category: "helper-state"
        tags: [perf-event scalar-policy reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let value = "01234567"'
            '  helper-call "bpf_perf_event_read_value" perf_events 0 $value 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_perf_event_read_value' requires arg3 = 24"
    }
    {
        name: "perf-event-read-value-rejects-dynamic-size"
        category: "helper-state"
        tags: [perf-event scalar-policy dynamic reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let value = "012345678901234567890123"'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_perf_event_read_value" perf_events 0 $value $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_perf_event_read_value' requires arg3 = 24"
    }
    {
        name: "syscall-helpers"
        category: "helper-state"
        tags: [syscall helper-call]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  let name = "init_task\u{0}"'
            '  let btf_name = "task_struct"'
            '  let out = "00000000"'
            '  helper-call "bpf_sys_bpf" 0 $attr 8'
            '  helper-call "bpf_kallsyms_lookup_name" $name 10 0 $out'
            '  helper-call "bpf_btf_find_by_name_kind" $btf_name 11 4 0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "syscall-helper-rejects-zero-attr-size"
        category: "helper-state"
        tags: [syscall scalar-policy reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  helper-call "bpf_sys_bpf" 0 $attr 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 166 arg2 must be > 0"
    }
    {
        name: "syscall-helper-rejects-dynamic-zero-attr-size"
        category: "helper-state"
        tags: [syscall scalar-policy dynamic branch reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  let selector = (helper-call "bpf_sys_bpf" 0 $attr 8)'
            '  let size = (if $selector == 0 { 0 } else { 8 })'
            '  helper-call "bpf_sys_bpf" 0 $attr $size'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 166 arg2 must be > 0"
    }
    {
        name: "syscall-helper-rejects-kallsyms-flags"
        category: "helper-state"
        tags: [syscall flags reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let name = "init_task\u{0}"'
            '  let out = "00000000"'
            '  helper-call "bpf_kallsyms_lookup_name" $name 10 1 $out'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_kallsyms_lookup_name' requires arg2 = 0"
    }
    {
        name: "syscall-helper-rejects-dynamic-kallsyms-flags"
        category: "helper-state"
        tags: [syscall flags dynamic reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  let name = "init_task\u{0}"'
            '  let out = "00000000"'
            '  let flags = (helper-call "bpf_sys_bpf" 0 $attr 8)'
            '  helper-call "bpf_kallsyms_lookup_name" $name 10 $flags $out'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_kallsyms_lookup_name' requires arg2 = 0"
    }
    {
        name: "lsm-bprm-opts-set"
        category: "helper-state"
        tags: [lsm helper-call]
        requires: [kernel-btf]
        target: "lsm:bprm_check_security"
        program: [
            '{|ctx|'
            '  helper-call "bpf_bprm_opts_set" $ctx.arg.bprm 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-bprm-opts-set-rejects-flags"
        category: "helper-state"
        tags: [lsm flags reject]
        requires: [kernel-btf]
        target: "lsm:bprm_check_security"
        program: [
            '{|ctx|'
            '  helper-call "bpf_bprm_opts_set" $ctx.arg.bprm 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_bprm_opts_set' requires arg1 flags to contain only BPF_F_BPRM_* bits"
    }
    {
        name: "lsm-bprm-opts-set-rejects-dynamic-flags"
        category: "helper-state"
        tags: [lsm flags dynamic reject]
        requires: [kernel-btf]
        target: "lsm:bprm_check_security"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_bprm_opts_set" $ctx.arg.bprm $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_bprm_opts_set' requires arg1 flags to contain only BPF_F_BPRM_* bits"
    }
    {
        name: "kprobe-override-return"
        category: "helper-state"
        tags: [kprobe helper-call]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_override_return" $ctx 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretprobe-rejects-override-return"
        category: "helper-state"
        tags: [kretprobe helper-call reject]
        target: "kretprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_override_return" $ctx 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_override_return' is only valid in kprobe, kprobe.multi, and ksyscall programs"
    }
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
    {
        name: "callback-bpf-loop-rejects-out-of-range-return"
        category: "callbacks"
        tags: [helper-call callback bpf-loop return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb| 2 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "callback-bpf-loop-allows-prefix-params"
        category: "callbacks"
        tags: [helper-call callback bpf-loop prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i|'
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
        name: "callback-bpf-loop-rejects-extra-declared-param"
        category: "callbacks"
        tags: [helper-call callback bpf-loop reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb extra| $i } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 3 parameters, but the callback ABI supplies 2"
    }
    {
        name: "callback-for-each-map-elem"
        category: "callbacks"
        tags: [helper-call callback map array]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $v.seen | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-rejects-extra-declared-param"
        category: "callbacks"
        tags: [helper-call callback map array reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb extra|'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 5 parameters, but the callback ABI supplies 4"
    }
    {
        name: "callback-for-each-map-elem-rejects-out-of-range-return"
        category: "callbacks"
        tags: [helper-call callback map array return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb| 2 } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "callback-for-each-map-elem-record-context"
        category: "callbacks"
        tags: [helper-call callback map array record]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $cb.threshold | count'
            '    0'
            '  } { threshold: 7 } 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-allows-prefix-params"
        category: "callbacks"
        tags: [helper-call callback map array prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v|'
            '    $v.seen | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-map-btf-field"
        category: "callbacks"
        tags: [helper-call callback map btf kernel-btf]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $m.id | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-map-sum-elem-count-for-each-map-callback"
        category: "callbacks"
        tags: [kfunc helper-call callback map btf kernel-btf accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    let total = (kfunc-call "bpf_map_sum_elem_count" $m)'
            '    $total | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-map-sum-elem-count-rejects-stack-pointer"
        category: "callbacks"
        tags: [kfunc callback map pointer reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let stack_map = "abcdefgh"'
            '  kfunc-call "bpf_map_sum_elem_count" $stack_map'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_map_sum_elem_count' arg0 expects kernel pointer, got Stack"
    }
    {
        name: "callback-for-each-map-elem-rejects-nonzero-flags"
        category: "callbacks"
        tags: [helper-call callback map array flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    0'
            '  } "ctx" 1 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_for_each_map_elem' requires arg3 flags to be 0"
    }
    {
        name: "callback-for-each-map-elem-rejects-dynamic-flags"
        category: "callbacks"
        tags: [helper-call callback map array flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    0'
            '  } "ctx" $flags --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_for_each_map_elem' requires arg3 flags to be 0"
    }
    {
        name: "callback-find-vma-btf-field"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    $vma.vm_start | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-find-vma-rejects-nonzero-flags"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf flags reject]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    0'
            '  } "ctx" 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_find_vma' requires arg4 flags to be 0"
    }
    {
        name: "callback-find-vma-rejects-dynamic-flags"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf flags reject]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    0'
            '  } "ctx" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_find_vma' requires arg4 flags to be 0"
    }
    {
        name: "callback-find-vma-rejects-extra-declared-param"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf reject]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb extra|'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 4 parameters, but the callback ABI supplies 3"
    }
    {
        name: "callback-find-vma-rejects-out-of-range-return"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf return reject]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb| 2 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "callback-find-vma-rejects-non-task-pointer"
        category: "callbacks"
        tags: [helper-call callback btf reject]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx 0 {|task vma cb|'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_find_vma' arg0 expects task pointer"
    }
    {
        name: "callback-find-vma-record-context"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf record]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    $cb.cookie | count'
            '    0'
            '  } { cookie: 11 } 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-find-vma-allows-prefix-params"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf prefix-arity accept]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma|'
            '    $task.pid | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain-dynptr-data-guarded"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf null-check accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb|'
            '    let data = (helper-call "bpf_dynptr_data" $dyn 0 4)'
            '    if $data {'
            '      $data | count'
            '    }'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain-dynptr-data-requires-null-check"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf null-check reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb|'
            '    helper-call "bpf_dynptr_data" $dyn 0 4 | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "callback-user-ringbuf-drain-allows-prefix-params"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain-rejects-extra-declared-param"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb extra| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 3 parameters, but the callback ABI supplies 2"
    }
    {
        name: "callback-user-ringbuf-drain-rejects-out-of-range-return"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 2 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "callback-user-ringbuf-drain-record-context"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf record]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| $cb.limit } { limit: 1 } 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "reserved-events-rejects-user-ringbuf"
        category: "maps"
        tags: [helper-call callback user-ringbuf reject reserved-name]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" events {|dyn cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map name 'events' is reserved"
    }
    {
        name: "helper-call-kind-rejects-implied-map-kind"
        category: "maps"
        tags: [helper-call map-kind reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" demo_ringbuf 0 --kind ringbuf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind is only supported for helpers whose map family is ambiguous"
    }
    {
        name: "csum-diff-allows-null-zero-side"
        category: "helper-state"
        tags: [csum null-pointer tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 0 0 0 0 | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "csum-diff-rejects-null-nonzero-side"
        category: "helper-state"
        tags: [csum null-pointer reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 4 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 28 arg0 requires arg1 = 0 when arg0 is null"
    }
]
