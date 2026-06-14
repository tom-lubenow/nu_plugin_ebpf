export const VERIFIER_DIFF_FIXTURES_3723_3726 = [
    {
        name: "global-define-type-array-record-any-field"
        category: "globals"
        tags: [globals records arrays any closure get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  ((global-get seen_entries) | any {|row| $row.pid == 9 })'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-all-field"
        category: "globals"
        tags: [globals records arrays all closure get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  ((global-get seen_entries) | all {|row| $row.pid > 0 })'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-any-length"
        category: "globals"
        tags: [globals arrays string any closure str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bbb"] | global-define --type "array{string:8:2}" names'
            '  ((global-get names) | any {|x| ($x | str length) == 3 })'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-all-length"
        category: "globals"
        tags: [globals arrays binary bytes all closure length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | all {|x| ($x | bytes length) == 4 })'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
