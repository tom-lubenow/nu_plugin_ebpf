export const VERIFIER_DIFF_FIXTURES_3588_3591 = [
    {
        name: "global-define-type-array-record-list-field-last-selects-tail"
        category: "globals"
        tags: [globals records arrays list last get length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | last)'
            '  (($row.id == 2) and (($row.samples | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-list-field-drop-last-selects-head"
        category: "globals"
        tags: [globals records arrays list drop last get length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | drop 1 | last)'
            '  (($row.id == 1) and (($row.samples | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-last-selects-tail"
        category: "globals"
        tags: [globals records arrays string last get str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-define --type "array{record{id:int,name:string:15}:2}" entries'
            '  let row = ((global-get entries) | last)'
            '  (($row.id == 2) and (($row.name | str length) == 3))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-drop-last-selects-head"
        category: "globals"
        tags: [globals records arrays string drop last get str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-define --type "array{record{id:int,name:string:15}:2}" entries'
            '  let row = ((global-get entries) | drop 1 | last)'
            '  (($row.id == 1) and (($row.name | str length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
