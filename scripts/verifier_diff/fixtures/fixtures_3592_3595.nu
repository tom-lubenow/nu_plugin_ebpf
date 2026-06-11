export const VERIFIER_DIFF_FIXTURES_3592_3595 = [
    {
        name: "global-define-type-array-record-list-field-get-head-element"
        category: "globals"
        tags: [globals records arrays list get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | get 0)'
            '  (($row.id == 1) and (($row.samples | get 1) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-list-field-get-tail-element"
        category: "globals"
        tags: [globals records arrays list get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | get 1)'
            '  (($row.id == 2) and (($row.samples | get 0) == 3))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-get-head-length"
        category: "globals"
        tags: [globals records arrays string get str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-define --type "array{record{id:int,name:string:15}:2}" entries'
            '  let row = ((global-get entries) | get 0)'
            '  (($row.id == 1) and (($row.name | str length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-get-tail-length"
        category: "globals"
        tags: [globals records arrays string get str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-define --type "array{record{id:int,name:string:15}:2}" entries'
            '  let row = ((global-get entries) | get 1)'
            '  (($row.id == 2) and (($row.name | str length) == 3))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
