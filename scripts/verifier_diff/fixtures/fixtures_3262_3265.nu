export const VERIFIER_DIFF_FIXTURES_3262_3265 = [
    {
        name: "global-define-type-array-bool-length"
        category: "globals"
        tags: [globals arrays bool length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-first"
        category: "globals"
        tags: [globals arrays bool first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  ((global-get flags) | first) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-append-last"
        category: "globals"
        tags: [globals arrays bool append last global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | append true | last) == true)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-prepend-first"
        category: "globals"
        tags: [globals arrays bool prepend first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | prepend true | first) == true)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
