export const VERIFIER_DIFF_FIXTURES_3584_3587 = [
    {
        name: "global-define-type-array-record-list-field-skip-first-length"
        category: "globals"
        tags: [globals records arrays list skip first length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ samples: [1 2] } { samples: [3 4] }] | global-define --type "array{record{samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | skip 1 | first)'
            '  (($row.samples | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-list-field-prepend-first-length"
        category: "globals"
        tags: [globals records arrays list prepend first length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ samples: [1 2] } { samples: [3 4] }] | global-define --type "array{record{samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | prepend { samples: [5 6] } | first)'
            '  (($row.samples | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-skip-first-length"
        category: "globals"
        tags: [globals records arrays string skip first str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ name: "aa" } { name: "bb" }] | global-define --type "array{record{name:string:15}:2}" entries'
            '  let row = ((global-get entries) | skip 1 | first)'
            '  (($row.name | str length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-prepend-first-length"
        category: "globals"
        tags: [globals records arrays string prepend first str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ name: "aa" } { name: "bb" }] | global-define --type "array{record{name:string:15}:2}" entries'
            '  let row = ((global-get entries) | prepend { name: "cc" } | first)'
            '  (($row.name | str length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
