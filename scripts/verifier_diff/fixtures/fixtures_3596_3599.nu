export const VERIFIER_DIFF_FIXTURES_3596_3599 = [
    {
        name: "global-set-array-record-list-field-get-tail-element"
        category: "globals"
        tags: [globals records arrays list get global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-set entries'
            '  let row = ((global-get entries) | get 1)'
            '  (($row.id == 2) and (($row.samples | get 0) == 3))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-array-record-string-field-get-tail-length"
        category: "globals"
        tags: [globals records arrays string get str length global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-set entries'
            '  let row = ((global-get entries) | get 1)'
            '  (($row.id == 2) and (($row.name | str length) == 3))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-array-record-list-builder-list-field-get-tail-element"
        category: "globals"
        tags: [globals records arrays list append get global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | global-set entries'
            '  let row = ((global-get entries) | get 1)'
            '  (($row.id == 2) and (($row.samples | get 1) == 4))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-array-record-spread-string-field-get-tail-length"
        category: "globals"
        tags: [globals records arrays string list-spread get str length global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | global-set entries'
            '  let row = ((global-get entries) | get 1)'
            '  (($row.id == 2) and (($row.name | str length) == 3))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
