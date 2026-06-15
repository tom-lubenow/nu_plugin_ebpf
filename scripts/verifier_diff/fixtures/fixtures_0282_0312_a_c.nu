const VERIFIER_DIFF_FIXTURES_0282_0312_A_C = [
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
