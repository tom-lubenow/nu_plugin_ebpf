const VERIFIER_DIFF_FIXTURES_1126_1156 = [
    {
        name: "map-define-kptr-rejects-array-field"
        category: "maps"
        tags: [maps map-define kptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --value-type "record{tasks:array{record{task:kptr:task_struct}:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed kptr"
    }
    {
        name: "map-define-bpf-wq-slot"
        category: "maps"
        tags: [maps map-define bpf_wq accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-bpf-wq-slot-rejects-queue"
        category: "maps"
        tags: [maps map-define bpf_wq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind queue --value-type "record{work:bpf_wq,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "contains bpf_wq, which is only supported for hash, array, and lru-hash maps"
    }
    {
        name: "map-define-bpf-wq-rejects-array-field"
        category: "maps"
        tags: [maps map-define bpf_wq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work_items:array{bpf_wq:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_wq"
    }
    {
        name: "bpf-wq-kfunc-init-start"
        category: "helper-state"
        tags: [bpf_wq kfunc-call accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '    kfunc-call "bpf_wq_start" $entry.work 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bpf-wq-init-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [bpf_wq kfunc-call nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "bpf-wq-init-rejects-non-wq-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{lock:bpf_spin_lock,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.lock work_items 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-init-rejects-dynamic-non-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items_dyn --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items_dyn --kind array)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let work = (if $selector == 0 { $entry.work } else { 0 })'
            '    kfunc-call "bpf_wq_init" $work work_items_dyn 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-start-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [bpf_wq kfunc-call nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  kfunc-call "bpf_wq_start" $entry 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "bpf-wq-start-rejects-non-wq-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{lock:bpf_spin_lock,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_start" $entry.lock 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_start' arg0 expects bpf_wq pointer"
    }
    {
        name: "bpf-wq-start-rejects-stack-value"
        category: "helper-state"
        tags: [bpf_wq kfunc-call stack reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let work = "0123456789abcdef"'
            '  kfunc-call "bpf_wq_start" $work 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_start' arg0 expects bpf_wq pointer"
    }
    {
        name: "bpf-wq-set-callback-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  kfunc-call "bpf_wq_set_callback_impl" $entry {|map key work| 0} 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "bpf-wq-set-callback-rejects-non-wq-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{lock:bpf_spin_lock,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.lock {|map key work| 0} 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-set-callback-rejects-stack-value"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback stack reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let work = "0123456789abcdef"'
            '  kfunc-call "bpf_wq_set_callback_impl" $work {|map key work| 0} 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-set-callback-rejects-dynamic-non-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items_dyn_cb --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items_dyn_cb --kind array)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let work = (if $selector == 0 { $entry.work } else { 0 })'
            '    kfunc-call "bpf_wq_set_callback_impl" $work {|map key work| 0} 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
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
