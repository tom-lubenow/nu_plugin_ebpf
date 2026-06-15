const VERIFIER_DIFF_FIXTURES_1126_1156_B = [
    {
        name: "bpf-wq-kfunc-set-callback"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} 0 0'
            '    kfunc-call "bpf_wq_start" $entry.work 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bpf-wq-kfunc-set-callback-allows-prefix-params"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key| 0} 0 0'
            '    kfunc-call "bpf_wq_start" $entry.work 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bpf-wq-set-callback-rejects-out-of-i32-return"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 2147483648} 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "bpf-wq-kfunc-set-callback-rejects-extra-declared-param"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work extra| 0} 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 4 parameters, but the callback ABI supplies 3"
    }
    {
        name: "bpf-wq-init-rejects-mismatched-map"
        category: "helper-state"
        tags: [bpf_wq kfunc-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work other_items 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc-call 'bpf_wq_init' requires arg1 map 'other_items'"
    }
    {
        name: "bpf-wq-init-accepts-phi-joined-same-map-value-source"
        category: "helper-state"
        tags: [bpf_wq kfunc-call phi dynamic branch accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind hash --key-type u32 --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.pid'
            '  let left_key = $base_key'
            '  let right_key = $base_key'
            '  let first = ($left_key | map-get work_items --kind hash)'
            '  let second = ($right_key | map-get work_items --kind hash)'
            '  let entry = (if $selector == 0 { $first } else { $second })'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bpf-wq-init-rejects-phi-joined-mismatched-map-value-source"
        category: "helper-state"
        tags: [bpf_wq kfunc-call phi dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind hash --key-type u32 --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  map-define other_work_items --kind hash --key-type u32 --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.pid'
            '  let first = ($base_key | map-get work_items --kind hash)'
            '  let second = ($base_key | map-get other_work_items --kind hash)'
            '  let entry = (if $selector == 0 { $first } else { $second })'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc-call 'bpf_wq_init' requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-init-rejects-nonzero-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_init' arg2 must be known zero"
    }
]
