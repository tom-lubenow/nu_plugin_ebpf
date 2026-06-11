export const VERIFIER_DIFF_FIXTURES_3660_3663 = [
    {
        name: "global-define-type-array-record-list-global-set-tail-element"
        category: "globals"
        tags: [globals records arrays list global-define global-set get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" entries'
            '  [{ id: 5 samples: [6 7] } { id: 8 samples: [9 10] }] | global-set entries'
            '  let entries = (global-get entries)'
            '  let row = ($entries | get 1)'
            '  (($row.id == 8) and (($row.samples | get 0) == 9))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-global-set-tail-length"
        category: "globals"
        tags: [globals records arrays string global-define global-set get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bb" }] | global-define --type "array{record{id:int,name:string:15}:2}" entries'
            '  [{ id: 5 name: "cc" } { id: 8 name: "ddd" }] | global-set entries'
            '  let entries = (global-get entries)'
            '  let row = ($entries | get 1)'
            '  (($row.id == 8) and (($row.name | str length) == 3))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-array-record-list-global-set-tail-element"
        category: "globals"
        tags: [globals records arrays list global-define zero-fill global-set get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{record{id:int,samples:list:int:2}:2}" entries'
            '  [{ id: 5 samples: [6 7] } { id: 8 samples: [9 10] }] | global-set entries'
            '  let entries = (global-get entries)'
            '  let row = ($entries | get 1)'
            '  (($row.id == 8) and (($row.samples | get 1) == 10))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-array-record-string-global-set-tail-length"
        category: "globals"
        tags: [globals records arrays string global-define zero-fill global-set get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{record{id:int,name:string:15}:2}" entries'
            '  [{ id: 5 name: "cc" } { id: 8 name: "ddd" }] | global-set entries'
            '  let entries = (global-get entries)'
            '  let row = ($entries | get 1)'
            '  (($row.id == 8) and (($row.name | str length) == 3))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
