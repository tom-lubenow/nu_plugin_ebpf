const VERIFIER_DIFF_FIXTURES_1157_1187_A = [
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
]
