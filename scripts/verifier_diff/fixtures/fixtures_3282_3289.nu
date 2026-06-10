export const VERIFIER_DIFF_FIXTURES_3282_3289 = [
    {
        name: "global-define-type-array-record-length"
        category: "globals"
        tags: [globals records arrays length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-first-field"
        category: "globals"
        tags: [globals records arrays first get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | first).cpu) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-last-field"
        category: "globals"
        tags: [globals records arrays last get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | last).cpu) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-take-last-field"
        category: "globals"
        tags: [globals records arrays take last get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | take 1 | last).cpu) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-skip-first-field"
        category: "globals"
        tags: [globals records arrays skip first get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | skip 1 | first).cpu) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-reverse-first-field"
        category: "globals"
        tags: [globals records arrays reverse first get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | reverse | first).cpu) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-append-last-field"
        category: "globals"
        tags: [globals records arrays append last get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | append { pid: 11 cpu: 4 } | last).cpu) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-prepend-first-field"
        category: "globals"
        tags: [globals records arrays prepend first get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | prepend { pid: 11 cpu: 4 } | first).cpu) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
