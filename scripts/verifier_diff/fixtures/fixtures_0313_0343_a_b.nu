const VERIFIER_DIFF_FIXTURES_0313_0343_A_B = [
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
]
