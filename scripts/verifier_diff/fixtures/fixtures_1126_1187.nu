const VERIFIER_DIFF_FIXTURES_1126_1187 = [
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
    {
        name: "map-define-bpf-refcount-rejects-queue"
        category: "maps"
        tags: [maps map-define bpf_refcount reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind queue --value-type "record{refs:bpf_refcount,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "contains bpf_refcount, which is currently supported for hash, array, and lru-hash maps"
    }
    {
        name: "map-define-bpf-refcount-rejects-array-field"
        category: "maps"
        tags: [maps map-define bpf_refcount reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind array --value-type "record{refs:array{bpf_refcount:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_refcount"
    }
    {
        name: "map-define-graph-root-schema"
        category: "maps"
        tags: [maps map-define graph accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-rejects-top-level-graph-root-schema"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "must wrap bpf_list_head in a map-value record field"
    }
    {
        name: "map-define-rejects-bare-graph-root"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head'"
    }
    {
        name: "map-define-rejects-bare-rbtree-node"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{node:bpf_rb_node,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'node' type spec 'bpf_rb_node'"
    }
    {
        name: "map-define-bpf-timer-rejects-array-field"
        category: "maps"
        tags: [maps map-define timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timers:array{bpf_timer:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_timer"
    }
    {
        name: "timer-map-define-lowers-init-start-cancel"
        category: "helper-state"
        tags: [timer map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind array'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 0}'
            '    helper-call "bpf_timer_start" $entry.timer 1000 0'
            '    helper-call "bpf_timer_cancel" $entry.timer'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-start-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [timer map-define nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  helper-call "bpf_timer_start" $entry 1000 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "timer-init-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [timer map-define nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  helper-call "bpf_timer_init" $entry timers 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "timer-set-callback-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [timer callback map-define nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  helper-call "bpf_timer_set_callback" $entry {|timer key val| 0}'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "timer-cancel-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [timer map-define nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  helper-call "bpf_timer_cancel" $entry'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "timer-init-rejects-mismatched-owner-map"
        category: "helper-state"
        tags: [timer map-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  map-define other_timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer other_timers 0 --kind array'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg1 map 'other_timers'"
    }
    {
        name: "timer-init-accepts-phi-joined-same-map-value-source"
        category: "helper-state"
        tags: [timer map-define phi dynamic branch accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.pid'
            '  let left_key = $base_key'
            '  let right_key = $base_key'
            '  let first = ($left_key | map-get timers --kind hash)'
            '  let second = ($right_key | map-get timers --kind hash)'
            '  let entry = (if $selector == 0 { $first } else { $second })'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-init-rejects-phi-joined-mismatched-map-value-source"
        category: "helper-state"
        tags: [timer map-define phi dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  map-define other_timers --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.pid'
            '  let first = ($base_key | map-get timers --kind hash)'
            '  let second = ($base_key | map-get other_timers --kind hash)'
            '  let entry = (if $selector == 0 { $first } else { $second })'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-callback-uses-trailing-value-param"
        category: "helper-state"
        tags: [timer callback accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      $val.cookie | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-callback-allows-prefix-params"
        category: "helper-state"
        tags: [timer callback prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key|'
            '      $key | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-callback-map-btf-field"
        category: "helper-state"
        tags: [timer callback btf kernel-btf]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      $timer.id | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-callback-rejects-extra-declared-param"
        category: "helper-state"
        tags: [timer callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val extra| 0}'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 4 parameters, but the callback ABI supplies 3"
    }
    {
        name: "timer-callback-rejects-nonzero-return"
        category: "helper-state"
        tags: [timer callback return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 1}'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "timer-init-rejects-invalid-clock-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 99 --kind array'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_init' requires arg2 flags to be CLOCK_REALTIME, CLOCK_MONOTONIC, or CLOCK_BOOTTIME"
    }
    {
        name: "timer-start-rejects-invalid-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_start" $entry.timer 1000 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_start' requires arg2 flags to contain only BPF_F_TIMER_* bits"
    }
    {
        name: "timer-init-rejects-dynamic-clock-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers $flags --kind array'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_init' requires arg2 flags to be CLOCK_REALTIME, CLOCK_MONOTONIC, or CLOCK_BOOTTIME"
    }
    {
        name: "timer-start-rejects-dynamic-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_start" $entry.timer 1000 $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_start' requires arg2 flags to contain only BPF_F_TIMER_* bits"
    }
    {
        name: "source-kfunc-iter-num-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  let item = (kfunc-call "bpf_iter_num_next" $iter)'
            '  if $item { 0 }'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-num-user-function-new-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept user-function]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def iter-new [iter start end] {'
            '    kfunc-call "bpf_iter_num_new" $iter $start $end'
            '    0'
            '  }'
            '  def iter-destroy [iter] {'
            '    kfunc-call "bpf_iter_num_destroy" $iter'
            '    0'
            '  }'
            '  let iter = "0123456789abcdef"'
            '  iter-new $iter 0 4'
            '  let item = (kfunc-call "bpf_iter_num_next" $iter)'
            '  if $item { 0 }'
            '  iter-destroy $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-num-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_num_next' requires a matching bpf_iter_num_new"
    }
    {
        name: "source-kfunc-iter-num-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_num iterator"
    }
    {
        name: "source-kfunc-iter-num-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_num_destroy' requires a matching bpf_iter_num_new"
    }
    {
        name: "source-kfunc-iter-num-rejects-reinit-live-slot"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  kfunc-call "bpf_iter_num_new" $iter 4 8'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_num stack object slot"
    }
    {
        name: "source-kfunc-iter-num-rejects-reinit-after-conditional-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  }'
            '  kfunc-call "bpf_iter_num_new" $iter 4 8'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_num stack object slot"
    }
]
