const VERIFIER_DIFF_FIXTURES_0282_0312_A = [
    {
        name: "global-define-type-list-builder-initializer"
        category: "globals"
        tags: [globals list append global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let initial = ([] | append 11 | append 22)'
            '  $initial | global-define --type "list:int:4" samples'
            '  let samples = (global-get samples)'
            '  ($samples | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-global-define-data"
        category: "globals"
        tags: [globals scalar forward global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let before = (global-get state)'
            '  7 | global-define state'
            '  $before | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-typed-global-define-bss"
        category: "globals"
        tags: [globals scalar typed forward global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let before = (global-get state)'
            '  global-define --type int state'
            '  $before | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-typed-record-global-define-bss"
        category: "globals"
        tags: [globals records typed forward global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let before = (global-get state)'
            '  global-define --type "record{pid:int}" state'
            '  $before.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-typed-record-global-define-data"
        category: "globals"
        tags: [globals records typed forward upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut seed = { pid: 0 }'
            '  $seed.pid = 8'
            '  let before = (global-get state)'
            '  $seed | global-define --type "record{pid:int}" state'
            '  $before.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
