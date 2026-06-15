const VERIFIER_DIFF_FIXTURES_0282_0312_A_B = [
    {
        name: "global-define-type-zero-list-root-appends"
        category: "globals"
        tags: [globals list upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "list:int:2" samples'
            '  mut samples = (global-get samples)'
            '  $samples.0 = 11'
            '  $samples.1 = 22'
            '  $samples.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-initialized-list-root-append"
        category: "globals"
        tags: [globals list upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "list:int:4" samples'
            '  mut samples = (global-get samples)'
            '  $samples.2 = 33'
            '  $samples.2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-root-list-append-past-capacity-rejects"
        category: "globals"
        tags: [globals list upsert global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11] | global-define --type "list:int:1" samples'
            '  mut samples = (global-get samples)'
            '  $samples.1 = 22'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot append beyond numeric list capacity 1"
    }
    {
        name: "global-set-mutated-root-numeric-list"
        category: "globals"
        tags: [globals list upsert global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "list:int:2" samples'
            '  mut samples = (global-get samples)'
            '  $samples.0 = 11'
            '  $samples | global-set samples'
            '  let persisted = (global-get samples)'
            '  $persisted.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
