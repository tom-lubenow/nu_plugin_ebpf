const VERIFIER_DIFF_FIXTURES_0251_0281_B_C = [
    {
        name: "global-define-type-bool-not-initializer"
        category: "globals"
        tags: [globals scalar bool global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let enabled = (not false)'
            '  $enabled | global-define --type bool enabled'
            '  let stored = (global-get enabled)'
            '  if $stored { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-add-initializer"
        category: "globals"
        tags: [globals scalar global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let sum = (3 + 4)'
            '  $sum | global-define --type int sum'
            '  let stored = (global-get sum)'
            '  $stored | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-record-field-initializer"
        category: "globals"
        tags: [globals records scalar global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = { pid: 7 }'
            '  $state.pid | global-define --type int seen_pid'
            '  let stored = (global-get seen_pid)'
            '  $stored | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-bool-initializer-rejects"
        category: "globals"
        tags: [globals scalar bool global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  true | global-define --type int state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'int' initializer requires a i64-compatible constant"
    }
    {
        name: "global-define-type-list-int-initializer"
        category: "globals"
        tags: [globals list global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "list:int:4" samples'
            '  let samples = (global-get samples)'
            '  ($samples | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-list-int-bool-item-rejects"
        category: "globals"
        tags: [globals list bool global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true] | global-define --type "list:int:4" samples'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'list:int:4' initializer[0] requires a numeric constant item, found bool"
    }
    {
        name: "global-define-type-bound-list-int-initializer"
        category: "globals"
        tags: [globals list global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let initial = [11 22]'
            '  $initial | global-define --type "list:int:4" samples'
            '  let samples = (global-get samples)'
            '  ($samples | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
