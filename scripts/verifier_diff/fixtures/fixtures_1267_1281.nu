const VERIFIER_DIFF_FIXTURES_1267_1281 = [
    {
        name: "source-kfunc-percpu-obj-drop-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let meta = ($ctx.pid + 1)'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj $meta'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $task 0'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-obj-drop-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_obj_drop_impl" $task 0'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-double-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-percpu-obj-drop-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    } else {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-list-push-front-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
