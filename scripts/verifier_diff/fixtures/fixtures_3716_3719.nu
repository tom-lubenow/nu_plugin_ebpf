export const VERIFIER_DIFF_FIXTURES_3716_3719 = [
    {
        name: "global-define-type-array-record-where-field-length"
        category: "globals"
        tags: [globals records arrays where closure get length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | where {|row| $row.pid == 9 } | length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-where-length"
        category: "globals"
        tags: [globals records arrays string where closure str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ name: "aa" } { name: "bbb" }] | global-define --type "array{record{name:string:8}:2}" names'
            '  (((global-get names) | where {|row| ($row.name | str length) == 3 } | length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-bytes-where-length"
        category: "globals"
        tags: [globals records arrays binary bytes where closure length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ payload: 0x[01 02] } { payload: 0x[03 04] }] | global-define --type "array{record{payload:bytes:4}:2}" packets'
            '  (((global-get packets) | where {|row| ($row.payload | bytes length) == 4 } | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-where-first-rejects"
        category: "globals"
        tags: [globals records arrays where closure first diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | where {|row| $row.pid == 9 } | first).pid == 9)'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "metadata-only shape consumers"
    }
]
