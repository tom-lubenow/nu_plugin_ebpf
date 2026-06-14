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
    {
        name: "global-get-before-later-global-set-bss"
        category: "globals"
        tags: [globals scalar forward global-set zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let before = (global-get state)'
            '  7 | global-set state'
            '  $before | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-root-scalar-data"
        category: "globals"
        tags: [globals scalar global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  7 | global-set seen_pid'
            '  let pid = (global-get seen_pid)'
            '  $pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-root-scalar-bss"
        category: "globals"
        tags: [globals scalar zero-fill global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | global-set seen_zero'
            '  let value = (global-get seen_zero)'
            '  $value | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-root-string-field-get"
        category: "globals"
        tags: [globals string global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "hello" | global-set seen_name'
            '  let name = (global-get seen_name)'
            '  ($name | str length) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-root-binary-get"
        category: "globals"
        tags: [globals binary bytes global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | global-set scratch'
            '  let b = (global-get scratch)'
            '  ($b | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-runtime-record-list-field-get"
        category: "globals"
        tags: [globals records list global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,samples:list:int:2}" src_state'
            '  let src = (global-get src_state)'
            '  $src | global-set dst_state'
            '  let dst = (global-get dst_state)'
            '  (($dst.samples | get 1) + $dst.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
