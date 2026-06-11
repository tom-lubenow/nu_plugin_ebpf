export const VERIFIER_DIFF_FIXTURES_3576_3583 = [
    {
        name: "global-define-type-array-record-list-field-first-length"
        category: "globals"
        tags: [globals records arrays list first length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ samples: [1 2] } { samples: [3 4] }] | global-define --type "array{record{samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | first)'
            '  (($row.samples | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-list-field-take-last-length"
        category: "globals"
        tags: [globals records arrays list take last length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ samples: [1 2] } { samples: [3 4] }] | global-define --type "array{record{samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | take 1 | last)'
            '  (($row.samples | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-list-field-reverse-first-length"
        category: "globals"
        tags: [globals records arrays list reverse first length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ samples: [1 2] } { samples: [3 4] }] | global-define --type "array{record{samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | reverse | first)'
            '  (($row.samples | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-list-field-append-last-length"
        category: "globals"
        tags: [globals records arrays list append last length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ samples: [1 2] } { samples: [3 4] }] | global-define --type "array{record{samples:list:int:2}:2}" entries'
            '  let row = ((global-get entries) | append { samples: [5 6] } | last)'
            '  (($row.samples | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-first-length"
        category: "globals"
        tags: [globals records arrays string first str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ name: "aa" } { name: "bb" }] | global-define --type "array{record{name:string:15}:2}" entries'
            '  let row = ((global-get entries) | first)'
            '  (($row.name | str length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-take-last-length"
        category: "globals"
        tags: [globals records arrays string take last str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ name: "aa" } { name: "bb" }] | global-define --type "array{record{name:string:15}:2}" entries'
            '  let row = ((global-get entries) | take 1 | last)'
            '  (($row.name | str length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-reverse-first-length"
        category: "globals"
        tags: [globals records arrays string reverse first str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ name: "aa" } { name: "bb" }] | global-define --type "array{record{name:string:15}:2}" entries'
            '  let row = ((global-get entries) | reverse | first)'
            '  (($row.name | str length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-append-last-length"
        category: "globals"
        tags: [globals records arrays string append last str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ name: "aa" } { name: "bb" }] | global-define --type "array{record{name:string:15}:2}" entries'
            '  let row = ((global-get entries) | append { name: "cc" } | last)'
            '  (($row.name | str length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
