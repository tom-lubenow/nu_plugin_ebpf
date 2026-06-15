const VERIFIER_DIFF_FIXTURES_0313_0343_B = [
    {
        name: "global-set-array-record-initializer"
        category: "globals"
        tags: [globals records arrays global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-set seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-array-record-list-builder-initializer"
        category: "globals"
        tags: [globals records arrays append global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { pid: 7 cpu: 2 } | append { pid: 9 cpu: 3 })'
            '  $entries | global-set seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-array-record-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  [{ pid: 7 cpu: 2 }, ...$tail] | global-set seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-record-array-record-field-initializer"
        category: "globals"
        tags: [globals records arrays global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { entries: [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] } | global-set seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-empty-binary-without-type-rejects"
        category: "globals"
        tags: [globals binary global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define scratch'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "empty binary constants do not establish a fixed byte-buffer layout"
    }
    {
        name: "global-define-record-empty-binary-field-without-type-rejects"
        category: "globals"
        tags: [globals records binary global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 meta: { comm: 0x[] } } | global-define scratch'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'meta.comm'"
    }
    {
        name: "map-define-null-only-lookup-keeps-value-layout"
        category: "maps"
        tags: [maps map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define null_only --kind hash --value-type int'
            '  42 | map-put null_only 0 --kind hash'
            '  let entry = (0 | map-get null_only --kind hash)'
            '  if $entry { 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-max-entries"
        category: "maps"
        tags: [maps map-define max-entries accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define small_seen --kind hash --value-type int --max-entries 32'
            '  42 | map-put small_seen 0 --kind hash'
            '  let entry = (0 | map-get small_seen --kind hash)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-inferred-array-kind"
        category: "maps"
        tags: [maps map-define kind-inference accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define array_slots --kind array --value-type int --max-entries 32'
            '  42 | map-put array_slots 0'
            '  let entry = (0 | map-get array_slots)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-same-name-conflicting-kinds-rejects"
        category: "maps"
        tags: [maps kind-conflict reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  42 | map-put shared_resource 0 --kind array'
            '  let entry = (0 | map-get shared_resource --kind hash)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "conflicts with prior map kind"
    }
    {
        name: "map-operation-inferred-array-kind"
        category: "maps"
        tags: [maps kind-inference accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  42 | map-put operation_slots 0 --kind array'
            '  let entry = (0 | map-get operation_slots)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
