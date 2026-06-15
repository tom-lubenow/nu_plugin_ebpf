const VERIFIER_DIFF_FIXTURES_0251_0281_B = [
    {
        name: "global-define-type-array-u32-first-count-length"
        category: "globals"
        tags: [globals arrays first length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | first 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-is-empty"
        category: "globals"
        tags: [globals arrays is-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-is-not-empty"
        category: "globals"
        tags: [globals arrays is-not-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (global-get ports) | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-last-count-get"
        category: "globals"
        tags: [globals arrays get first last global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | last 1) | get 0) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
