export const VERIFIER_DIFF_FIXTURES_3266_3272 = [
    {
        name: "global-define-type-array-bool-last"
        category: "globals"
        tags: [globals arrays bool last global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false] | global-define --type "array{bool:2}" flags'
            '  ((global-get flags) | last) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-take-last"
        category: "globals"
        tags: [globals arrays bool take last global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false] | global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | take 1 | last) == true)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-skip-first"
        category: "globals"
        tags: [globals arrays bool skip first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false] | global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | skip 1 | first) == false)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-drop-last"
        category: "globals"
        tags: [globals arrays bool drop last global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false] | global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | drop 1 | last) == true)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-reverse-first"
        category: "globals"
        tags: [globals arrays bool reverse first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false] | global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | reverse | first) == false)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-sort-first"
        category: "globals"
        tags: [globals arrays bool sort first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false] | global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | sort | first) == false)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-sort-reverse-first"
        category: "globals"
        tags: [globals arrays bool sort reverse first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false] | global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | sort --reverse | first) == true)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-find-true-length"
        category: "globals"
        tags: [globals arrays bool find length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false true] | global-define --type "array{bool:3}" flags'
            '  (((global-get flags) | find true | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-is-empty"
        category: "globals"
        tags: [globals arrays bool is-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  ((global-get flags) | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-is-not-empty"
        category: "globals"
        tags: [globals arrays bool is-not-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  ((global-get flags) | is-not-empty) == true'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
