const VERIFIER_DIFF_FIXTURES_1501_2000 = [
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
    {
        name: "csum-diff-rejects-null-dynamic-side"
        category: "helper-state"
        tags: [csum null-pointer dynamic reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let size = ((helper-call "bpf_get_prandom_u32") + 4)'
            '  helper-call "bpf_csum_diff" 0 $size 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 28 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "csum-diff-rejects-unaligned-size"
        category: "helper-state"
        tags: [csum scalar-policy reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 2 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
    }
    {
        name: "csum-diff-rejects-dynamic-unaligned-size"
        category: "helper-state"
        tags: [csum scalar-policy dynamic branch reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let size = (if $selector == 0 { 0 } else { 2 })'
            '  helper-call "bpf_csum_diff" 0 $size 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
    }
    {
        name: "redirect-neigh-allows-null-params"
        category: "helper-state"
        tags: [redirect-neigh null-pointer tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 0 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-neigh-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-neigh flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_neigh" 1 0 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg3 = 0"
    }
    {
        name: "redirect-neigh-rejects-null-nonzero-plen"
        category: "helper-state"
        tags: [redirect-neigh null-pointer reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 4 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null"
    }
    {
        name: "redirect-neigh-rejects-null-dynamic-plen"
        category: "helper-state"
        tags: [redirect-neigh null-pointer dynamic reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let plen = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_neigh" 1 0 $plen 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null"
    }
    {
        name: "redirect-peer-helper"
        category: "helper-state"
        tags: [redirect-peer tc-action accept source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_peer" 1 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-peer-rejects-nonzero-flags"
        category: "helper-state"
        tags: [redirect-peer flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_peer" 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' requires arg1 = 0"
    }
    {
        name: "redirect-helper-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect flags reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect" 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect' requires arg1 flags to contain only BPF_F_INGRESS"
    }
    {
        name: "clone-redirect-rejects-dynamic-flags"
        category: "helper-state"
        tags: [clone-redirect flags reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_clone_redirect" $ctx 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-map flags reject xdp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_map" tx_ports 0 $flags --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_map' requires arg2 flags"
    }
    {
        name: "redirect-peer-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-peer flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_peer" 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' requires arg1 = 0"
    }
    {
        name: "core-early-return"
        category: "language-core"
        tags: [control-flow return]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  if true { return 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-early-return"
        category: "language-core"
        tags: [control-flow return user-function]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def choose [x] {'
            '    if $x == 0 { return 7 }'
            '    9'
            '  }'
            '  choose 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-loop-break-continue"
        category: "language-core"
        tags: [control-flow loop break continue]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  for i in 0..3 {'
            '    if $i == 1 { continue }'
            '    if $i == 3 { break }'
            '    $sum = ($sum + $i)'
            '  }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-loop-early-return"
        category: "language-core"
        tags: [control-flow loop return]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut seen = 0'
            '  for i in 0..3 {'
            '    if $i == 2 { return $i }'
            '    $seen = $i'
            '  }'
            '  $seen'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-nested-loop-break-continue"
        category: "language-core"
        tags: [control-flow loop break continue]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  for i in 0..2 {'
            '    for j in 0..2 {'
            '      if $j == 1 { continue }'
            '      if $i == 2 { break }'
            '      $sum = ($sum + $i + $j)'
            '    }'
            '  }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-dynamic-range-loop-reject"
        category: "language-core"
        tags: [control-flow loop reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let end = $ctx.pid'
            '  for i in 0..$end {'
            '    $i | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Range end must be a compile-time known integer for eBPF loops"
    }
    {
        name: "core-literal-list-iterate"
        category: "language-core"
        tags: [control-flow loop aggregate list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  for item in [10 20 30] {'
            '    $sum = ($sum + $item)'
            '  }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-inline-bounded-loop"
        category: "language-core"
        tags: [control-flow loop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  if true { for i in 0..3 { $sum = ($sum + $i) } }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-bounded-loop"
        category: "language-core"
        tags: [control-flow loop user-function]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def sum [] {'
            '    mut total = 0'
            '    for i in 0..3 {'
            '      $total = ($total + $i)'
            '    }'
            '    $total'
            '  }'
            '  sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-list-iterate"
        category: "language-core"
        tags: [control-flow loop aggregate list user-function]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def sum_list [] {'
            '    mut sum = 0'
            '    for item in [10 20 30] {'
            '      $sum = ($sum + $item)'
            '    }'
            '    $sum'
            '  }'
            '  sum_list'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-null-compare-flow"
        category: "language-core"
        tags: [control-flow "null"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let maybe = null'
            '  if $maybe == null { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-spread"
        category: "language-core"
        tags: [aggregate list spread]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let xs = [1, 2]'
            '  let ys = [0, ...$xs, 3]'
            '  $ys | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-first-scalar"
        category: "language-core"
        tags: [aggregate list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-last-scalar"
        category: "language-core"
        tags: [aggregate list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-first-empty-reject"
        category: "language-core"
        tags: [aggregate list first reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | first'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first requires a non-empty stack-backed numeric list"
    }
    {
        name: "core-list-last-empty-reject"
        category: "language-core"
        tags: [aggregate list last reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | last'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last requires a non-empty stack-backed numeric list"
    }
    {
        name: "core-list-first-count"
        category: "language-core"
        tags: [aggregate list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first 2 | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-last-count"
        category: "language-core"
        tags: [aggregate list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-first-negative-count-reject"
        category: "language-core"
        tags: [aggregate list first reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first count must be non-negative"
    }
    {
        name: "core-list-last-negative-count-reject"
        category: "language-core"
        tags: [aggregate list last reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last count must be non-negative"
    }
    {
        name: "core-list-get-negative-index-reject"
        category: "language-core"
        tags: [aggregate list get reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let i = -1'
            '  [10 20 30] | get $i'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index must be non-negative"
    }
    {
        name: "core-list-get-out-of-bounds-reject"
        category: "language-core"
        tags: [aggregate list get reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | get 3'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index 3 is out of bounds"
    }
    {
        name: "core-list-take-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 2 | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-oversized-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 4 | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-zero-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 0 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-negative-count-reject"
        category: "language-core"
        tags: [aggregate list take reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "take count must be non-negative"
    }
    {
        name: "core-list-reverse"
        category: "language-core"
        tags: [aggregate list reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-reverse-after-take"
        category: "language-core"
        tags: [aggregate list reverse take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 2 | reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-uniq"
        category: "language-core"
        tags: [aggregate list uniq]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 10 30 20] | uniq | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-uniq-empty"
        category: "language-core"
        tags: [aggregate list uniq empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | uniq | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort"
        category: "language-core"
        tags: [aggregate list sort]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [30 10 20] | sort | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort-reverse"
        category: "language-core"
        tags: [aggregate list sort reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 30 20] | sort --reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort-capacity-reject"
        category: "language-core"
        tags: [aggregate list sort reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 0 16 | sort | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort supports stack-backed numeric lists with capacity <= 16"
    }
    {
        name: "core-list-compact"
        category: "language-core"
        tags: [aggregate list compact]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-compact-empty"
        category: "language-core"
        tags: [aggregate list compact empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact --empty | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-compact-column-reject"
        category: "language-core"
        tags: [aggregate list compact reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "compact does not accept column arguments"
    }
    {
        name: "core-record-list-compact-column-length"
        category: "language-core"
        tags: [aggregate record list compact column length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 8 } { pid: 9 cpu: 4 }] | compact cpu | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-compact-empty-column-length"
        category: "language-core"
        tags: [aggregate record list compact empty column length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [{ pid: 7 comm: "" } { pid: 8 comm: "nu" } { pid: 9 }] | compact --empty comm | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find"
        category: "language-core"
        tags: [aggregate list find]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | find 20 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find-missing"
        category: "language-core"
        tags: [aggregate list find empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | find 99 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-default"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-zero-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 0 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-oversized-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 4 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-negative-count-reject"
        category: "language-core"
        tags: [aggregate list drop reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "drop count must be non-negative"
    }
    {
        name: "core-list-skip-default"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-count"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-oversized-count"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip 4 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-negative-count-reject"
        category: "language-core"
        tags: [aggregate list skip reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skip count must be non-negative"
    }
    {
        name: "core-list-append"
        category: "language-core"
        tags: [aggregate list append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | append 40 | get 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-prepend"
        category: "language-core"
        tags: [aggregate list prepend]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | prepend 5 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-each"
        category: "language-core"
        tags: [aggregate list each closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | each {|x| $x + 1 } | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-where"
        category: "language-core"
        tags: [aggregate list where closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | where {|x| $x > 15 } | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-any"
        category: "language-core"
        tags: [aggregate list any closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | any {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all"
        category: "language-core"
        tags: [aggregate list all closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | all {|x| $x > 5 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-any-empty"
        category: "language-core"
        tags: [aggregate list any closure empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | any {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all-empty"
        category: "language-core"
        tags: [aggregate list all closure empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | all {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-append-capacity-reject"
        category: "language-core"
        tags: [aggregate list append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 0 59 | append 60 | get 60'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "append would exceed stack-backed numeric list capacity 60"
    }
    {
        name: "core-list-is-empty"
        category: "language-core"
        tags: [aggregate list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-length"
        category: "language-core"
        tags: [aggregate list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-length"
        category: "language-core"
        tags: [string list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-get"
        category: "language-core"
        tags: [string list get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | get 1 | str starts-with "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-first"
        category: "language-core"
        tags: [string list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | first | str starts-with "ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-last"
        category: "language-core"
        tags: [string list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | last | str starts-with "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-take"
        category: "language-core"
        tags: [string list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | take 2 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-skip"
        category: "language-core"
        tags: [string list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | skip 1 | str join "-" | str starts-with "cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-drop"
        category: "language-core"
        tags: [string list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | drop 1 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-first-count"
        category: "language-core"
        tags: [string list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | first 2 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-last-count"
        category: "language-core"
        tags: [string list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | last 2 | str join "-" | str starts-with "cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-reverse"
        category: "language-core"
        tags: [string list reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | reverse | str join "-" | str starts-with "ef-cd-ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-append"
        category: "language-core"
        tags: [string list append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | append "ef" | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-prepend"
        category: "language-core"
        tags: [string list prepend]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | prepend "zz" | str join "-" | str starts-with "zz-ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-uniq"
        category: "language-core"
        tags: [string list uniq]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ab" "ef" "cd"] | uniq | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-sort"
        category: "language-core"
        tags: [string list sort]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["cd" "aa" "ab"] | sort | str join "-" | str starts-with "aa-ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-sort-reverse"
        category: "language-core"
        tags: [string list sort reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["cd" "aa" "ab"] | sort --reverse | str join "-" | str starts-with "cd-ab-aa"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-find"
        category: "language-core"
        tags: [string list find]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef" "cd"] | find "cd" | str join "-" | str starts-with "cd-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-compact-empty"
        category: "language-core"
        tags: [string list compact empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "" "cd"] | compact --empty | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-sum"
        category: "language-core"
        tags: [aggregate list math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-integer-sum"
        category: "language-core"
        tags: [aggregate list seq math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 5 | math sum) == 15'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-negative-step-join"
        category: "language-core"
        tags: [aggregate list seq str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 5 -2 1 | str join "-" | str starts-with "5-3-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-float-join"
        category: "language-core"
        tags: [aggregate list seq float str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1.0 0.5 2.0 | str join "," | str starts-with "1.0,1.5,2.0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-float-metadata-transforms"
        category: "language-core"
        tags: [aggregate list seq float sort reverse find split-list str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let sort_ok = (seq 2.0 -0.5 1.0 | sort | str join "," | str starts-with "1.0,1.5,2.0")'
            '  let reverse_ok = (seq 1.0 0.5 2.0 | reverse | str join "," | str starts-with "2.0,1.5,1.0")'
            '  $sort_ok and ($reverse_ok and (((seq 1.0 0.5 2.0 | find 1.5 | length) == 1) and ((seq 1.0 0.5 2.0 | split list 1.5 | length) == 2)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-char-join"
        category: "language-core"
        tags: [aggregate list seq char str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq char e a | str join "-" | str starts-with "e-d-c-b-a"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-char-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq char reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq char A ~ | str join ""'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq char output exceeds fixed string-list capacity 60"
    }
    {
        name: "core-seq-date-join"
        category: "language-core"
        tags: [aggregate list seq date str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-01-05" --increment 2 | str join "," | str starts-with "2020-01-01,2020-01-03,2020-01-05"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-length"
        category: "language-core"
        tags: [aggregate list seq date length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq date --begin-date "2020-01-05" --end-date "2020-01-01" | length) == 5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-days-join"
        category: "language-core"
        tags: [aggregate list seq date days str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --days 5 --increment 2 | str join "," | str starts-with "2020-01-01,2020-01-03,2020-01-05"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-periods-join"
        category: "language-core"
        tags: [aggregate list seq date periods str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 4 --increment 3 | str join "," | str starts-with "2020-01-01,2020-01-04,2020-01-07,2020-01-10"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-format-join"
        category: "language-core"
        tags: [aggregate list seq date format str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --input-format "%m/%d/%Y" --output-format "%Y/%m/%d" --begin-date "01/01/2020" --end-date "01/03/2020" | str join "," | str starts-with "2020/01/01,2020/01/02,2020/01/03"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-duration-increment-join"
        category: "language-core"
        tags: [aggregate list seq date duration increment str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-01-02" --increment 6hr --output-format "%Y-%m-%d %H:%M:%S" | str join "," | str starts-with "2020-01-01 00:00:00,2020-01-01 06:00:00,2020-01-01 12:00:00,2020-01-01 18:00:00,2020-01-02 00:00:00"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-reverse-periods-join"
        category: "language-core"
        tags: [aggregate list seq date reverse periods str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 3 --increment 2 --reverse | str join "," | str starts-with "2020-01-01,2019-12-30,2019-12-28,2019-12-26,2019-12-24"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq date reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-03-15" | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date output exceeds fixed string-list capacity 60"
    }
    {
        name: "core-seq-date-periods-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq date periods reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 61 | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date output exceeds fixed string-list capacity 60"
    }
    {
        name: "core-list-math-product"
        category: "language-core"
        tags: [aggregate list math product]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [2 3 4] | math product'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min"
        category: "language-core"
        tags: [aggregate list math min]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math min'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-max"
        category: "language-core"
        tags: [aggregate list math max]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math max'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min-max-mixed-numeric"
        category: "language-core"
        tags: [aggregate list math min max float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1 2.5 3.5] | math min) == 1) and (([1.5 2.5 3] | math max) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-results-fill"
        category: "language-core"
        tags: [aggregate list math min max median float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1.5 2 3] | math min | fill --alignment right --character "0" --width 4 | str starts-with "01.5") and ([1 2.0 2] | math max | fill --alignment right --character "0" --width 4 | str starts-with "0002")) and (([1 3] | math median | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1.5 3.5 10] | math median | fill --alignment right --character "0" --width 4 | str starts-with "03.5"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-sum-product-fill"
        category: "language-core"
        tags: [aggregate list math sum product float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1.5 2] | math sum | fill --alignment right --character "0" --width 4 | str starts-with "03.5") and ([1.5 2] | math product | fill --alignment right --character "0" --width 4 | str starts-with "0003")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-avg-fill"
        category: "language-core"
        tags: [aggregate list math avg float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1 2 3] | math avg | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1.0 2] | math avg | fill --alignment right --character "0" --width 4 | str starts-with "01.5")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-avg-filesize-duration"
        category: "language-core"
        tags: [aggregate list math avg filesize duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1kb 2kb 2kb] | math avg | describe | str starts-with "filesize") and ([1sec 2sec 2sec] | math avg | describe | str starts-with "duration")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-sqrt-folded"
        category: "language-core"
        tags: [scalar aggregate list math sqrt float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (9 | math sqrt | fill --alignment right --character "0" --width 4 | str starts-with "0003") and ([4 2.25 9] | math sqrt | str join "," | str starts-with "2.0,1.5,3.0")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-exp-folded"
        category: "language-core"
        tags: [scalar aggregate list math exp float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0 | math exp | fill --alignment right --character "0" --width 4 | str starts-with "0001") and ([0 1] | math exp | str join "," | str starts-with "1.0,2.718281828459045")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-ln-folded"
        category: "language-core"
        tags: [scalar aggregate list math ln float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (1 | math ln | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([1 2] | math ln | str join "," | str starts-with "0.0,0.6931471805599453")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-log-folded"
        category: "language-core"
        tags: [scalar aggregate list math log float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (100 | math log 10 | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([16 8 4] | math log 2 | str join "," | str starts-with "4.0,3.0,2.0")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-trig-folded"
        category: "language-core"
        tags: [scalar aggregate list math sin cos tan float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((0 | math sin | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math cos | fill --alignment right --character "0" --width 4 | str starts-with "0001")) and ((0 | math tan | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([0 0] | math cos | str join "," | str starts-with "1.0,1.0"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-hyperbolic-folded"
        category: "language-core"
        tags: [scalar aggregate list math sinh cosh tanh float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((0 | math sinh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math cosh | fill --alignment right --character "0" --width 4 | str starts-with "0001")) and ((0 | math tanh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([0 0] | math cosh | str join "," | str starts-with "1.0,1.0"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-inverse-folded"
        category: "language-core"
        tags: [scalar aggregate list math inverse float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((0 | math arcsin | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (1 | math arccos | fill --alignment right --character "0" --width 4 | str starts-with "0000")) and ((0 | math arctan | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math arcsinh | fill --alignment right --character "0" --width 4 | str starts-with "0000"))) and (((1 | math arccosh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math arctanh | fill --alignment right --character "0" --width 4 | str starts-with "0000")) and ([0 1] | math arcsin | str join "," | str starts-with "0.0,1.5707963267948966"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-degrees-folded"
        category: "language-core"
        tags: [scalar aggregate list math degrees inverse sin cos tan float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((90 | math sin --degrees | fill --alignment right --character "0" --width 4 | str starts-with "0001") and (180 | math cos --degrees | fill --alignment right --character "0" --width 1 | str starts-with "-1")) and (45 | math tan --degrees | fill --alignment right --character "0" --width 1 | str starts-with "0.999")) and (((1 | math arcsin --degrees | fill --alignment right --character "0" --width 1 | str starts-with "90") and (-1 | math arccos --degrees | fill --alignment right --character "0" --width 1 | str starts-with "180")) and ((1 | math arctan -d | fill --alignment right --character "0" --width 1 | str starts-with "45") and ([0 1] | math arcsin -d | str join "," | str starts-with "0.0,90.0")))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-stats-folded"
        category: "language-core"
        tags: [aggregate list math variance stddev sample float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1 2 3 4 5] | math variance | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1 2 3 4 5] | math stddev --sample | fill --alignment right --character "0" --width 4 | str starts-with "1.581")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-filesize-duration"
        category: "language-core"
        tags: [aggregate list math filesize duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1kb 2kb] | math sum | describe | str starts-with "filesize") and (([1sec 2sec] | math sum | describe | str starts-with "duration"))) and ((([1kb 2] | math max | describe | str starts-with "filesize") and ([1sec 2] | math min) == 2) and (([1kb 2kb] | math median | describe | str starts-with "filesize") and ([1sec 2sec] | math median | describe | str starts-with "duration")))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-median"
        category: "language-core"
        tags: [aggregate list math median]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math median'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-median-mixed-numeric"
        category: "language-core"
        tags: [aggregate list math median float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1.5 3 10.5] | math median) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-math-median"
        category: "language-core"
        tags: [aggregate list seq math median]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 5 | math median'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-list-math-median"
        category: "language-core"
        tags: [aggregate list math median runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  let m = (seq 10 10 20 | append $n | math median)'
            '  ($m >= 10) and ($m <= 20)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-mode"
        category: "language-core"
        tags: [aggregate list math mode]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [5 1 5 2 1] | math mode | str join "-" | str starts-with "1-5"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-list-math-mode"
        category: "language-core"
        tags: [aggregate list math mode runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  (seq 1 1 3 | append $n | math mode | length) >= 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-mode-empty"
        category: "language-core"
        tags: [aggregate list math mode empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([] | math mode | length) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min-single"
        category: "language-core"
        tags: [aggregate list math min]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20] | math min'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-sum-empty-reject"
        category: "language-core"
        tags: [aggregate list math sum reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | math sum'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sum requires a non-empty stack-backed numeric list"
    }
    {
        name: "core-scalar-math-abs"
        category: "language-core"
        tags: [scalar math abs]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  -42 | math abs'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-abs-runtime"
        category: "language-core"
        tags: [scalar math abs runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | math abs) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-abs-float-folded"
        category: "language-core"
        tags: [scalar aggregate list math abs float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (-2.5 | math abs | fill --alignment right --character "0" --width 1 | str starts-with "2.5") and ([-2 -1.5] | math abs | str join "," | str starts-with "2,1.5")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-div-mod-runtime"
        category: "language-core"
        tags: [scalar math divide modulo runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = ((random int | bits and 255) + 1)'
            '  (($n / 3) >= 0) and (($n mod 3) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-arithmetic-runtime"
        category: "language-core"
        tags: [scalar math add subtract multiply runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 255)'
            '  ((($n + 7) - 3) * 2) >= 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-comparison-boolean-runtime"
        category: "language-core"
        tags: [scalar comparison boolean runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let a = (random int | bits and 255)'
            '  let b = (random int | bits and 255)'
            '  ($a == $b) or ($a != $b)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-comparison-ordering-runtime"
        category: "language-core"
        tags: [scalar comparison ordering runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let a = (random int | bits and 255)'
            '  let b = (random int | bits and 255)'
            '  ($a <= $b) or ($a > $b)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-comparison-grouped-boolean-runtime"
        category: "language-core"
        tags: [scalar comparison boolean runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let a = (random int | bits and 255)'
            '  let b = (random int | bits and 255)'
            '  (($a == $b) or ($a != $b)) and (($a <= $b) or ($a > $b)) and (($a < ($b + 1)) or ($a >= ($b + 1)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-if-logical-not"
        category: "language-core"
        tags: [control-flow "if" scalar logical "not" runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 1)'
            '  if (not ($n == 0)) { $n + 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer"
        category: "language-core"
        tags: [control-flow "match" scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 0 => 10, 1 => 20, _ => 30 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-bool"
        category: "language-core"
        tags: [control-flow "match" scalar bool runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let b = ((random int | bits and 1) == 1)'
            '  match $b { true => 10, false => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-nothing"
        category: "language-core"
        tags: [control-flow "match" scalar nothing runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let x = null'
            '  match $x { null => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-match-string"
        category: "language-core"
        tags: [control-flow "match" scalar string constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let s = "hi"'
            '  match $s { "hi" => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-tracked-string"
        category: "language-core"
        tags: [control-flow "match" scalar string runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "lo" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  match $left { "lo" => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-match-filesize"
        category: "language-core"
        tags: [control-flow "match" scalar filesize constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let size = 1kb'
            '  match $size { 1kb => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-equality-filesize-int"
        category: "language-core"
        tags: [scalar comparison filesize constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  if (1kb == 1000) { 10 } else { 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-match-duration"
        category: "language-core"
        tags: [control-flow "match" scalar duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let elapsed = 1ns'
            '  match $elapsed { 1ns => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-equality-duration-int"
        category: "language-core"
        tags: [scalar comparison duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  if (1ns == 1) { 10 } else { 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-or-pattern"
        category: "language-core"
        tags: [control-flow "match" "or-pattern" scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 0 | 1 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 0..2 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-explicit-step"
        category: "language-core"
        tags: [control-flow "match" range step scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 15)'
            '  match $n { 0..2..10 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-right-exclusive"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 0..<2 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-descending-right-exclusive"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 2..<0 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-open-lower"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { ..2 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-open-lower-right-exclusive"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { ..<2 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-open-upper"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 1.. => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-variable-binding"
        category: "language-core"
        tags: [control-flow "match" binding scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = ((random int | bits and 3) - 2)'
            '  match $n { $x => ($x + 1) }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-abs-sum"
        category: "language-core"
        tags: [aggregate list math abs sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [-2 -1 0 3] | math abs | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-abs-runtime"
        category: "language-core"
        tags: [aggregate list math abs runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | math abs | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-integer-identity"
        category: "language-core"
        tags: [aggregate list math ceil floor round]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([-2 0 3] | math ceil | math floor | math round | math sum) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-float-rounding"
        category: "language-core"
        tags: [scalar math ceil floor round float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(1.25 | math ceil) (-1.25 | math floor) (-2.5 | math round)] | math sum) == -3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-rounding"
        category: "language-core"
        tags: [aggregate list math round float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 1.5 -1.5] | math round | str join "," | str starts-with "1,2,-2"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-round-precision-folded"
        category: "language-core"
        tags: [scalar aggregate list math round precision float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((3.1415 | math round --precision 2 | fill --alignment right --character "0" --width 1 | str starts-with "3.14") and (314.15 | math round -p -1 | fill --alignment right --character "0" --width 1 | str starts-with "310")) and ([3.1415 -2.675] | math round -p 2 | str join "," | str starts-with "3.14,-2.68")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-integer-identity-runtime"
        category: "language-core"
        tags: [scalar math ceil floor round runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | math ceil | math floor | math round) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-integer-identity-runtime"
        category: "language-core"
        tags: [aggregate list math ceil floor round runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | math ceil | math floor | math round | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-floor-divide-constant"
        category: "language-core"
        tags: [scalar math floor-divide constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (5 // 2) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-integer-pow-runtime-base"
        category: "language-core"
        tags: [scalar math pow runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((random int | bits and 255) ** 2) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-binary"
        category: "language-core"
        tags: [scalar bits and or xor]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((5 | bits and 3) == 1) and ((5 | bits or 2) == 7) and ((5 | bits xor 3) == 6)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-binary-runtime"
        category: "language-core"
        tags: [scalar bits and or xor runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((random int | bits and 3) + (random int | bits or 2) + (random int | bits xor 1)) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary"
        category: "language-core"
        tags: [aggregate list bits and or xor]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits and 2 | bits or 8 | bits xor 1 | math sum) == 31'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-runtime"
        category: "language-core"
        tags: [aggregate list bits and or xor runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits and 3 | bits or 4 | bits xor 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits and or xor endian]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[ab cd] | bits and 0x[99 99] | bytes starts-with 0x[89 89]) and (0x[c0 ff ee] | bits or 0x[ff] --endian big | bytes starts-with 0x[c0 ff ff]) and (0x[ff] | bits xor 0x[12 34 56] --endian little | bytes starts-with 0x[ed 34 56])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits xor bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[aa] 0x[bb cc]] | bits xor 0x[ff] | bytes collect | bytes length) == 3) and (([0x[aa] 0x[bb cc]] | bits xor 0x[ff] | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-get-fold"
        category: "language-core"
        tags: [aggregate list binary bits xor get bytes starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01] 0x[02 03]] | bits xor 0x[ff] | get 1 | bytes starts-with 0x[fd fc]) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-signed"
        category: "language-core"
        tags: [scalar bits "not" signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (4 | bits not --signed) == -5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-signed-runtime"
        category: "language-core"
        tags: [scalar bits "not" signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits not --signed) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits "not" number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits not --number-bytes 1) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-signed"
        category: "language-core"
        tags: [aggregate list bits "not" signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits not --signed | math sum) == -12'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-signed-runtime"
        category: "language-core"
        tags: [aggregate list bits "not" signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits not --signed | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-default-runtime-reject"
        category: "language-core"
        tags: [scalar bits "not" default runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  random int | bits not'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not default auto-width integer mode requires compile-time known input"
    }
    {
        name: "core-scalar-bits-not-default"
        category: "language-core"
        tags: [scalar bits "not"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits not) == 251) and ((256 | bits not) == 65279) and ((65536 | bits not) == 4294901759) and ((4294967296 | bits not) == 140733193388031)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-number-bytes"
        category: "language-core"
        tags: [scalar bits "not" number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits not --number-bytes 8) == 140737488355323) and ((-130 | bits not --number-bytes 1) == 129)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits "not" signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[ff 00 7f] | bits not | bytes starts-with 0x[00 ff 80]) and (0x[aa 55] | bits not --number-bytes 8 | bytes starts-with 0x[55 aa]) and (0x[c3] | bits not --signed --number-bytes 8 | bytes starts-with 0x[3c])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[ff] 0x[00 01]] | bits not | bytes collect | bytes length) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-binary-first-last-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" first last bytes length starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[ff] 0x[00 01]] | bits not | first | bytes length) == 1) and (([0x[ff] 0x[00 01]] | bits not | last | bytes starts-with 0x[ff fe]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-binary-empty-predicate-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[]] | bits not | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-default"
        category: "language-core"
        tags: [aggregate list bits "not"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 256 -129] | bits not | math sum) == 65658'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-signed-i64"
        category: "language-core"
        tags: [scalar bits shl shr signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits shl 1 --signed --number-bytes 8) == 8) and ((-8 | bits shr 1 --signed --number-bytes 8) == -4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-i64"
        category: "language-core"
        tags: [aggregate list bits shl signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits shl 1 --signed --number-bytes 8 | math sum) == 18'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits shr signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shr 1 --signed --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-number-bytes"
        category: "language-core"
        tags: [scalar bits shl shr signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((255 | bits shl 1 --number-bytes 1) == 254) and ((-65 | bits shr 1 --number-bytes 1) == -33) and ((127 | bits shl 1 --signed --number-bytes 1) == -2) and ((128 | bits shr 1 --signed --number-bytes 1) == -64) and ((4294967296 | bits shl 1 --number-bytes 8) == 8589934592)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-rotate-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits shl shr rol ror signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[4f f4] | bits shl 4 | bytes starts-with 0x[ff 40]) and (0x[4f f4] | bits shr 4 --signed --number-bytes 8 | bytes starts-with 0x[04 ff]) and (0x[c0 ff ee] | bits rol 10 --signed --number-bytes 8 | bytes starts-with 0x[ff bb 03]) and (0x[ff bb 03] | bits ror 10 --number-bytes 8 | bytes starts-with 0x[c0 ff ee])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-rotate-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits shl ror bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[80] 0x[01 02]] | bits shl 1 | bytes collect | bytes length) == 3) and (([0x[80] 0x[01 02]] | bits ror 1 | bytes collect | bytes length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-number-bytes"
        category: "language-core"
        tags: [aggregate list bits shl number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([127 128 -129] | bits shl 1 --number-bytes 1 | math sum) == 252'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-number-bytes-runtime"
        category: "language-core"
        tags: [aggregate list bits shl number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shl 1 --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-fixed-runtime"
        category: "language-core"
        tags: [aggregate list bits shl signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shl 1 --signed --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-unsigned-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits shr number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shr 1 --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-signed-i64-runtime"
        category: "language-core"
        tags: [scalar bits shr signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits shr 1 --signed --number-bytes 8) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits shl number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits shl 1 --number-bytes 1) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-unsigned-i64-left-u32-runtime"
        category: "language-core"
        tags: [scalar bits shl number-bytes runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.pid | bits shl 1 --number-bytes 8) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-default"
        category: "language-core"
        tags: [scalar bits shl shr default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((128 | bits shl 1) == 0) and ((-129 | bits shr 1) == -65) and ((4294967296 | bits shl 1) == 8589934592)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-default-runtime-reject"
        category: "language-core"
        tags: [scalar bits shl default runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl default auto-width shifts require compile-time known integer input"
    }
    {
        name: "core-scalar-bits-shift-unsigned-i64-runtime"
        category: "language-core"
        tags: [scalar bits shr number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shr 1 --number-bytes 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-signed-i64"
        category: "language-core"
        tags: [scalar bits rol ror signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((1 | bits rol 1 --signed --number-bytes 8) == 2) and ((1 | bits ror 1 --signed --number-bytes 8) == -9223372036854775808) and ((1 | bits rol 64 --signed --number-bytes 8) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-i64"
        category: "language-core"
        tags: [aggregate list bits rol signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits rol 1 --signed --number-bytes 8 | math sum) == 18'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits ror signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --signed --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-number-bytes"
        category: "language-core"
        tags: [scalar bits rol ror signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((127 | bits rol 1 --number-bytes 1) == 254) and ((-65 | bits ror 1 --number-bytes 1) == -33) and ((1 | bits ror 32 --number-bytes 4) == 1) and ((1 | bits ror 1 --signed --number-bytes 1) == -128) and ((4294967296 | bits ror 1 --number-bytes 8) == 2147483648)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-number-bytes"
        category: "language-core"
        tags: [aggregate list bits rol number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([127 128 -129] | bits rol 1 --number-bytes 1 | math sum) == 253'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-number-bytes-runtime"
        category: "language-core"
        tags: [aggregate list bits ror number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-fixed-runtime"
        category: "language-core"
        tags: [aggregate list bits ror signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --signed --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-signed-i64-runtime"
        category: "language-core"
        tags: [scalar bits rol signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits rol 1 --signed --number-bytes 8) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits ror number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits ror 1 --number-bytes 1) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-unsigned-i64-left-u32-runtime"
        category: "language-core"
        tags: [scalar bits rol number-bytes runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.pid | bits rol 1 --number-bytes 8) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-default"
        category: "language-core"
        tags: [scalar bits rol ror default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((128 | bits rol 1) == 1) and ((-129 | bits rol 1) == -257) and ((4294967296 | bits ror 1) == 2147483648)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-default-runtime-reject"
        category: "language-core"
        tags: [scalar bits rol default runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits rol 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol default auto-width rotates require compile-time known integer input"
    }
    {
        name: "core-scalar-bits-rotate-unsigned-i64-runtime-reject"
        category: "language-core"
        tags: [scalar bits ror number-bytes runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits ror 1 --number-bytes 8'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror unsigned --number-bytes 8 requires compile-time known integer input"
    }
    {
        name: "core-null-length"
        category: "language-core"
        tags: ["null" length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  null | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-length"
        category: "language-core"
        tags: [binary length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-length"
        category: "language-core"
        tags: [binary bytes length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-length-join"
        category: "language-core"
        tags: [binary list bytes length join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03] 0x[]] | bytes length | str join "-" | str starts-with "2-1-0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-starts-with"
        category: "language-core"
        tags: [binary bytes starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-ends-with"
        category: "language-core"
        tags: [binary bytes ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes ends-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-starts-with"
        category: "language-core"
        tags: [binary list bytes starts-with get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes starts-with 0x[03] | get 1) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-ends-with"
        category: "language-core"
        tags: [binary list bytes ends-with get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes ends-with 0x[02] | get 0) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of"
        category: "language-core"
        tags: [binary bytes index-of]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-end"
        category: "language-core"
        tags: [binary bytes index-of end]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --end 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-index-of"
        category: "language-core"
        tags: [binary list bytes index-of get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 02 02]] | bytes index-of 0x[02] | get 1) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-index-of-end"
        category: "language-core"
        tags: [binary list bytes index-of end get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[02 01 02] 0x[03 04]] | bytes index-of --end 0x[02] | get 0) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-all-join"
        category: "language-core"
        tags: [binary bytes index-of all join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --all 0x[02] | str join "-" | str starts-with "1-3"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-all-end-join"
        category: "language-core"
        tags: [binary bytes index-of all end join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --all --end 0x[02] | str join "-" | str starts-with "3-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-reverse-starts-with"
        category: "language-core"
        tags: [binary bytes reverse starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes reverse | bytes starts-with 0x[03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-reverse-empty-length"
        category: "language-core"
        tags: [binary bytes reverse empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes reverse | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse"
        category: "language-core"
        tags: [binary list bytes reverse get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes reverse | get 0 | bytes starts-with 0x[02]) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes reverse empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes reverse unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-list-length"
        category: "language-core"
        tags: [binary list bytes reverse empty_list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes reverse | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-list-is-empty"
        category: "language-core"
        tags: [binary list bytes reverse empty_list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes reverse | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-get"
        category: "language-core"
        tags: [binary list bytes reverse unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | get 1 | bytes starts-with 0x[03 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-get-length"
        category: "language-core"
        tags: [binary list bytes reverse empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-last"
        category: "language-core"
        tags: [binary list bytes reverse unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | last | bytes starts-with 0x[03 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-first-length"
        category: "language-core"
        tags: [binary list bytes reverse empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-build-starts-with"
        category: "language-core"
        tags: [binary bytes build starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build 0x[01 02] 0x[03] 4 | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-build-empty-length"
        category: "language-core"
        tags: [binary bytes build empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-starts-with"
        category: "language-core"
        tags: [binary bytes at starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04] | bytes at 1..2 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-explicit-step-starts-with"
        category: "language-core"
        tags: [binary bytes at range step starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04 05 06] | bytes at 1..3..4 | bytes starts-with 0x[02 03 04 05]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-empty-length"
        category: "language-core"
        tags: [binary bytes at empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02] | bytes at 1..0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-collect"
        category: "language-core"
        tags: [binary list bytes at collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | bytes at 0..0 | bytes collect | bytes starts-with 0x[01 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes at empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes at 1..0 | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes at unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes at 0..2 | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-unequal-get"
        category: "language-core"
        tags: [binary list bytes at unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes at 0..2 | get 1 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-empty-get-length"
        category: "language-core"
        tags: [binary list bytes at empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes at 1..0 | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-unequal-last"
        category: "language-core"
        tags: [binary list bytes at unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes at 0..2 | last | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-empty-first-length"
        category: "language-core"
        tags: [binary list bytes at empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes at 1..0 | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-add-starts-with"
        category: "language-core"
        tags: [binary bytes add starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 04] | bytes add 0x[02 03] --index 1 | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-add-empty-length"
        category: "language-core"
        tags: [binary bytes add empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes add 0x[] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-collect"
        category: "language-core"
        tags: [binary list bytes add collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes add 0x[ff] --index 1 | bytes collect | bytes starts-with 0x[01 ff 02 ff]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes add empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes add 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes add unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes add 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-unequal-get"
        category: "language-core"
        tags: [binary list bytes add unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes add 0x[] | get 1 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-empty-get-length"
        category: "language-core"
        tags: [binary list bytes add empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes add 0x[] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-unequal-last"
        category: "language-core"
        tags: [binary list bytes add unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes add 0x[] | last | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-empty-first-length"
        category: "language-core"
        tags: [binary list bytes add empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes add 0x[] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-collect"
        category: "language-core"
        tags: [binary list bytes remove collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb]] | bytes remove 0x[10] | bytes collect | bytes starts-with 0x[aa bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes remove empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes remove unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10 20]] | bytes remove 0x[10] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-get"
        category: "language-core"
        tags: [binary list bytes remove unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes remove 0x[ff] | get 1 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-get-length"
        category: "language-core"
        tags: [binary list bytes remove empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-last"
        category: "language-core"
        tags: [binary list bytes remove unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes remove 0x[ff] | last | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-first-length"
        category: "language-core"
        tags: [binary list bytes remove empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-collect"
        category: "language-core"
        tags: [binary list bytes replace collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb]] | bytes replace 0x[10] 0x[a0] | bytes collect | bytes starts-with 0x[a0 aa a0 bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes replace empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes replace unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-get"
        category: "language-core"
        tags: [binary list bytes replace unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | get 1 | bytes starts-with 0x[bb cc]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-get-length"
        category: "language-core"
        tags: [binary list bytes replace empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-last"
        category: "language-core"
        tags: [binary list bytes replace unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | last | bytes starts-with 0x[bb cc]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-first-length"
        category: "language-core"
        tags: [binary list bytes replace empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-remove-starts-with"
        category: "language-core"
        tags: [binary bytes remove starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa 10 bb 10] | bytes remove --all 0x[10] | bytes starts-with 0x[aa bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-remove-empty-length"
        category: "language-core"
        tags: [binary bytes remove empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10] | bytes remove 0x[10] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-replace-starts-with"
        category: "language-core"
        tags: [binary bytes replace starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa 10 bb 10] | bytes replace --all 0x[10] 0x[a0] | bytes starts-with 0x[a0 aa a0]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-replace-empty-length"
        category: "language-core"
        tags: [binary bytes replace empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10] | bytes replace 0x[10] 0x[] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-starts-with"
        category: "language-core"
        tags: [binary bytes collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[11] 0x[33] 0x[44]] | bytes collect 0x[01] | bytes starts-with 0x[11 01 33]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-empty-length"
        category: "language-core"
        tags: [binary bytes collect empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[]] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-sort-collect"
        category: "language-core"
        tags: [binary list sort bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[03] 0x[01] 0x[02]] | sort | bytes collect | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-length"
        category: "language-core"
        tags: [binary list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-is-empty"
        category: "language-core"
        tags: [binary list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01]] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-is-not-empty"
        category: "language-core"
        tags: [binary list is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01]] | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-is-empty"
        category: "language-core"
        tags: [binary is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-is-not-empty"
        category: "language-core"
        tags: [binary is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-is-empty"
        category: "language-core"
        tags: [scalar int is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0 | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-is-not-empty"
        category: "language-core"
        tags: [scalar bool duration is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (false | is-not-empty) and (0sec | is-not-empty)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-append-collect"
        category: "language-core"
        tags: [binary list append bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | append 0x[03] | bytes collect | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-prepend-collect"
        category: "language-core"
        tags: [binary list prepend bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | prepend 0x[00] | bytes collect | bytes starts-with 0x[00 01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-reverse-collect"
        category: "language-core"
        tags: [binary list reverse bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | reverse | bytes collect | bytes starts-with 0x[03 02 01]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-uniq-collect"
        category: "language-core"
        tags: [binary list uniq bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[01]] | uniq | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-find-collect"
        category: "language-core"
        tags: [binary list find bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03] 0x[02]] | find 0x[02] | bytes collect | bytes starts-with 0x[02 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-take-collect"
        category: "language-core"
        tags: [binary list take bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | take 2 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-skip-collect"
        category: "language-core"
        tags: [binary list skip bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | skip 1 | bytes collect | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-drop-collect"
        category: "language-core"
        tags: [binary list drop bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | drop 1 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-first-collect"
        category: "language-core"
        tags: [binary list first bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | first 2 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-last-collect"
        category: "language-core"
        tags: [binary list last bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | last 2 | bytes collect | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-get-starts-with"
        category: "language-core"
        tags: [binary list get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | get 1 | bytes starts-with 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-compact-collect"
        category: "language-core"
        tags: [binary list compact bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[] 0x[02]] | compact --empty | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-collect-starts-with"
        category: "language-core"
        tags: [binary bytes split collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 2d 2d 62 2d 2d 63] | bytes split "--" | bytes collect 0x[20] | bytes starts-with 0x[61 20 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-part-collect-length"
        category: "language-core"
        tags: [binary bytes split empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-collect-length"
        category: "language-core"
        tags: [binary bytes split unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-get"
        category: "language-core"
        tags: [binary bytes split unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | get 1 | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-get-length"
        category: "language-core"
        tags: [binary bytes split empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-last"
        category: "language-core"
        tags: [binary bytes split unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | last | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-first-length"
        category: "language-core"
        tags: [binary bytes split empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-string-separator-unequal-last"
        category: "language-core"
        tags: [binary bytes split string separator unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 2d 2d 62 62] | bytes split "--" | last | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-input-length"
        category: "language-core"
        tags: [binary bytes split empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes split 0x[20] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-is-empty"
        category: "language-core"
        tags: [string is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "" | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length"
        category: "language-core"
        tags: [string str length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length-grapheme-clusters"
        category: "language-core"
        tags: [string str length grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "🇯🇵ほげ" | str length --grapheme-clusters'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length-chars"
        category: "language-core"
        tags: [string str length chars]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ("Amélie" | str length --chars) == 7'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-sum"
        category: "language-core"
        tags: [string list str length sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "bb"] | str length | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-grapheme-clusters-sum"
        category: "language-core"
        tags: [string list str length grapheme-clusters sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["🇯🇵" "ほげ"] | str length --grapheme-clusters | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-chars-sum"
        category: "language-core"
        tags: [string list str length chars sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (["Amélie" "字"] | str length --chars | math sum) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with"
        category: "language-core"
        tags: [string str starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-too-long"
        category: "language-core"
        tags: [string str starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | str starts-with "abcdefghijklmnopqrstu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-starts-with-tracked-length"
        category: "language-core"
        tags: [string str starts-with runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str starts-with "hello"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-ignore-case"
        category: "language-core"
        tags: [string str starts-with ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str starts-with --ignore-case "ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-starts-with-join"
        category: "language-core"
        tags: [string list str starts-with join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "xbc"] | str starts-with "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with"
        category: "language-core"
        tags: [string str ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str ends-with "def"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-too-long"
        category: "language-core"
        tags: [string str ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | str ends-with "abcdef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-ends-with-tracked-length"
        category: "language-core"
        tags: [string str ends-with runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str ends-with "lo"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-ignore-case"
        category: "language-core"
        tags: [string str ends-with ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str ends-with --ignore-case "CD"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-ends-with-join"
        category: "language-core"
        tags: [string list str ends-with join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "abx"] | str ends-with "c" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains"
        category: "language-core"
        tags: [string str contains]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str contains "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-contains-tracked-length"
        category: "language-core"
        tags: [string str contains runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str contains "ll"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-contains-join"
        category: "language-core"
        tags: [string list str contains join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "def"] | str contains "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-contains-ignore-case-join"
        category: "language-core"
        tags: [string list str contains ignore-case join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["Abc" "def"] | str contains --ignore-case "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-missing"
        category: "language-core"
        tags: [string str contains]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str contains "zz"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-ignore-case"
        category: "language-core"
        tags: [string str contains ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str contains --ignore-case "bc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-distance"
        category: "language-core"
        tags: [string str distance]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "nushell" | str distance "nutshell"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-join-scalar"
        category: "language-core"
        tags: [string str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str join "-" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-join"
        category: "language-core"
        tags: [string list str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-scalar-list-join"
        category: "language-core"
        tags: [string list scalar str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 1.5 1kb 1sec 0x[01 02] true null] | str join ":" | str starts-with "1:1.5:1.0 kB:1sec:[1, 2]:true:"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-aggregate-list-join"
        category: "language-core"
        tags: [string list aggregate record str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let records = ([{a: 1 b: 2} {c: 3}] | str join ":")'
            '  let lists = ([[1 2] [3]] | str join ":")'
            '  (($records | str starts-with "{a: 1") and ($records | str contains "b: 2}:{c: 3}")) and (($lists | str starts-with "[1") and ($lists | str contains "2]:[3]"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-fill-right"
        category: "language-core"
        tags: [string fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ab" | fill --alignment right --character "0" --width 5 | str starts-with "000ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-int-fill-right"
        category: "language-core"
        tags: [int fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  42 | fill --alignment right --character "0" --width 5 | str starts-with "00042"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-unsigned-int-fill"
        category: "language-core"
        tags: [int runtime fill context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | fill | str starts-with "0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-fill-right"
        category: "language-core"
        tags: [float fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1.25 | fill --alignment right --character "0" --width 6 | str starts-with "001.25"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-filesize-fill-right"
        category: "language-core"
        tags: [filesize fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1kb | fill --alignment right --character "_" --width 8 | str starts-with "____1000"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-named-prompt"
        category: "language-core"
        tags: [string char named]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char prompt | str starts-with "▶"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-named-extra-string-args"
        category: "language-core"
        tags: [string char named rest]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char prompt ignored 1f354 | str starts-with "▶"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-unicode-codepoints"
        category: "language-core"
        tags: [string char unicode]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --unicode 1F468 200D 1F466 | str starts-with "👨‍👦"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-integer-codepoints"
        category: "language-core"
        tags: [string char integer]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --integer 65 66 | str starts-with "AB"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-fill-center-join"
        category: "language-core"
        tags: [string list fill center join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "bc"] | fill --alignment center --character "_" --width 4 | str join "," | str starts-with "_a__,_bc_"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-int-list-fill-right-join"
        category: "language-core"
        tags: [int list fill right join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 23] | fill --alignment right --character "0" --width 3 | str join "," | str starts-with "001,023"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-mixed-list-fill-right-join"
        category: "language-core"
        tags: [int float filesize string list fill right join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 1.5 1kb "x"] | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "0001,01.5,1000,000x"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-string-group-join"
        category: "language-core"
        tags: [list split-list string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b" "x" "c" "d" "x" "e" "f"] | split list "x" | get 1 | str join "-" | str starts-with "c-d"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-after-string-group-join"
        category: "language-core"
        tags: [list split-list after string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x" "c" "x" "e" "f"] | split list --split after "x" | get 1 | str join "-" | str starts-with "c-x"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-before-string-group-join"
        category: "language-core"
        tags: [list split-list before string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b" "x" "c" "x" "d"] | split list --split before "x" | get 1 | str join "-" | str starts-with "x-c"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-regex-after-string-group-join"
        category: "language-core"
        tags: [list split-list regex after string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x1" "c" "x22" "e" "f"] | split list --regex --split after "x\\d+" | get 1 | str join "-" | str starts-with "c-x22"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-heterogeneous-materialized-reject"
        category: "language-core"
        tags: [aggregate list split-list reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x" "b" "c" "x" "d"] | split list "x"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list result requires homogeneous fixed-layout groups"
    }
    {
        name: "core-string-split-chars-join"
        category: "language-core"
        tags: [string split chars join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a🇯🇵b" | split chars | str join "-" | str starts-with "a-🇯-🇵-b"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-chars-grapheme-join"
        category: "language-core"
        tags: [string split chars grapheme join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a🇯🇵b" | split chars --grapheme-clusters | str join "-" | str starts-with "a-🇯🇵-b"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-words-join"
        category: "language-core"
        tags: [string split words join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello, to the world!" | split words | str join "-" | str starts-with "hello-to-the-world"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-words-min-utf8-join"
        category: "language-core"
        tags: [string split words min utf8 join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a é ee" | split words --min-word-length 2 --utf-8-bytes | str join "-" | str starts-with "é-ee"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-nested-metadata"
        category: "language-core"
        tags: [string list split chars words nested join length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let chars = (["ab" "cd"] | split chars | str join ":")'
            '  let words = (["a b" "c d e"] | split words | str join ":")'
            '  (($chars | str starts-with "[a") and ($chars | str contains "b]:[c")) and ((($words | str starts-with "[a") and ($words | str contains "e]")) and ((["ab" "cd"] | split chars | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-row-join"
        category: "language-core"
        tags: [string split row join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "alpha,beta,gamma" | split row "," | str join "-" | str starts-with "alpha-beta-gamma"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-row-number-join"
        category: "language-core"
        tags: [string list split row number join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a,b,c" "d,e"] | split row "," --number 2 | str join "-" | str starts-with "a-b,c-d-e"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-row-regex-number-join"
        category: "language-core"
        tags: [string list split row regex number join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a1b2c" "d33e"] | split row --regex "\\d+" --number 2 | str join "-" | str starts-with "a-b2c-d-e"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-stats-get-field"
        category: "language-core"
        tags: [string str stats record get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "Amélie Amelie" | str stats | get bytes'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-stats-unicode-width-get-field"
        category: "language-core"
        tags: [string str stats record get unicode-width]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "字\r\n字" | str stats | get unicode-width'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-length"
        category: "language-core"
        tags: [string str expand list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-path-length"
        category: "language-core"
        tags: [string str expand list length path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "C:\\{Users,Windows}" | str expand --path | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-empty-length"
        category: "language-core"
        tags: [string str expand list length empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{2..1}B" | str expand | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-get-length"
        category: "language-core"
        tags: [string str expand list get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | get 0 | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-get-content"
        category: "language-core"
        tags: [string str expand list get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | get 1 | str starts-with "AbDfG"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-range-get-content"
        category: "language-core"
        tags: [string str expand list get starts-with range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{08..10}B" | str expand | get 2 | str starts-with "A10B"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
