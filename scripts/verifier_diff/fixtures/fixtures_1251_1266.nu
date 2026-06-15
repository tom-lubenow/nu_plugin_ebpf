const VERIFIER_DIFF_FIXTURES_1251_1266 = [
    {
        name: "source-kfunc-obj-new-rejects-dynamic-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let type_id = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_obj_new_impl" $type_id 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be known constant"
    }
    {
        name: "source-kfunc-obj-new-rejects-zero-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 0 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be > 0"
    }
    {
        name: "source-kfunc-obj-new-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let meta = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 $meta)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_new_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-obj-drop-rejects-nonzero-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-obj-drop-rejects-double-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-obj-drop-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    } else {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-obj-drop-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
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
        name: "source-kfunc-obj-drop-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg0 reference already released"
    }
]
