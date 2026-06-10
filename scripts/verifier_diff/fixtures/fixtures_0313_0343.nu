const VERIFIER_DIFF_FIXTURES_0313_0343 = [
    {
        name: "global-define-type-nested-record-malformed-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{bad}}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'inner.bad' must use name:type syntax"
    }
    {
        name: "global-define-type-nested-record-invalid-array-length-rejects-path"
        category: "globals"
        tags: [globals records arrays diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{items:array{u32:x}}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'items' type spec 'array{u32:x}' has an invalid array length"
    }
    {
        name: "global-define-type-record-unmatched-braces-rejects-candidate"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{pid:u32" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'record{inner:record{pid:u32' has unmatched '{' braces"
    }
    {
        name: "global-define-type-record-partial-list-field-zero-fills"
        category: "globals"
        tags: [globals records list global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 } | global-define --type "record{pid:int,samples:list:int:2}" seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.samples | length) + $state.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-record-list-field-get"
        category: "globals"
        tags: [globals records list global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,samples:list:int:2}" seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.samples | get 1) + $state.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-nested-record-list-field-get"
        category: "globals"
        tags: [globals records list nested global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{pid:int,samples:list:int:2},cpu:u32}" seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.inner.samples | get 1) + $state.inner.pid + $state.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-record-list-field-append"
        category: "globals"
        tags: [globals records list upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{samples:list:int:2}" seen_state'
            '  mut state = (global-get seen_state)'
            '  $state.samples.0 = 11'
            '  $state.samples.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-array-field-initializer"
        category: "globals"
        tags: [globals records arrays global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 ports: [11 22] } | global-define --type "record{ports:array{u16:4},pid:int}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.ports | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-array-record-field-initializer"
        category: "globals"
        tags: [globals records arrays global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { entries: [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] } | global-define --type "record{entries:array{record{pid:int,cpu:u32}:2}}" seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-initializer"
        category: "globals"
        tags: [globals records arrays global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:u32}:2}" seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-list-builder-initializer"
        category: "globals"
        tags: [globals records arrays append global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { pid: 7 cpu: 2 } | append { pid: 9 cpu: 3 })'
            '  $entries | global-define --type "array{record{pid:int,cpu:u32}:2}" seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-nested-numeric-list-upsert"
        category: "globals"
        tags: [globals records arrays list upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{samples: [1 2]} {samples: [3 4]}] | global-define --type "array{record{samples:list:int:2}:2}" entries'
            '  mut entries = (global-get entries)'
            '  $entries.1.samples.1 = 9'
            '  $entries.1.samples.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-nested-string-field"
        category: "globals"
        tags: [globals records arrays string global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{name: "aa"} {name: "bb"}] | global-define --type "array{record{name:string:15}:2}" entries'
            '  let entries = (global-get entries)'
            '  $entries.1.name | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-nested-string-upsert"
        category: "globals"
        tags: [globals records arrays string upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{name: "aa"} {name: "bb"}] | global-define --type "array{record{name:string:15}:2}" entries'
            '  mut entries = (global-get entries)'
            '  $entries.1.name = "cc"'
            '  $entries.1.name | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  [{ pid: 7 cpu: 2 }, ...$tail] | global-define --type "array{record{pid:int,cpu:u32}:2}" seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "map-define-map-in-map-inner-template-object"
        category: "maps"
        tags: [maps map-define map-in-map accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-map-in-map-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_array --kind array-of-maps)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-inferred-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map kind-inference accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_array)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-dynamic-inner-lookup-accepts"
        category: "maps"
        tags: [maps map-define map-in-map dynamic-lookup accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    let value = (7 | map-get $inner)'
            '    if $value { $value | count }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-dynamic-inner-update-delete-accepts"
        category: "maps"
        tags: [maps map-define map-in-map dynamic-update dynamic-delete accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let outer_present = (0 | map-contains outer_array)'
            '  if $outer_present { 1 }'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    99 | map-put $inner 7'
            '    let inner_present = (7 | map-contains $inner)'
            '    if $inner_present { 1 }'
            '    7 | map-delete $inner'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
