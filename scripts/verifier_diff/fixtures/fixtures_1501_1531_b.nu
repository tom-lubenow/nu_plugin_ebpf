const VERIFIER_DIFF_FIXTURES_1501_1531_B = [
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
]
