const VERIFIER_DIFF_FIXTURES_0313_0343_A_C = [
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
]
