const VERIFIER_DIFF_FIXTURES_1126_1156_B_B = [
    {
        name: "bpf-wq-init-rejects-dynamic-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_init' arg2 must be known zero"
    }
    {
        name: "bpf-wq-start-rejects-nonzero-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_start" $entry.work 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_start' arg1 must be known zero"
    }
    {
        name: "bpf-wq-start-rejects-dynamic-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_start" $entry.work $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_start' arg1 must be known zero"
    }
    {
        name: "bpf-wq-set-callback-rejects-nonzero-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} 1 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_set_callback_impl' arg2 must be known zero"
    }
    {
        name: "bpf-wq-set-callback-rejects-dynamic-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} $flags 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_set_callback_impl' arg2 must be known zero"
    }
    {
        name: "bpf-wq-set-callback-rejects-nonzero-aux"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} 0 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_set_callback_impl' arg3 must be known zero"
    }
    {
        name: "bpf-wq-set-callback-rejects-dynamic-aux"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let aux = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} 0 $aux'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_set_callback_impl' arg3 must be known zero"
    }
    {
        name: "map-define-bpf-refcount-slot"
        category: "maps"
        tags: [maps map-define bpf_refcount accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind array --value-type "record{refs:bpf_refcount,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
