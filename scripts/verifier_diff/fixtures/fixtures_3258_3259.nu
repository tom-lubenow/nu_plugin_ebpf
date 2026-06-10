export const VERIFIER_DIFF_FIXTURES_3258_3259 = [
    {
        name: "global-define-type-array-bool-any-false"
        category: "globals"
        tags: [globals arrays bool any closure global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  (global-get flags) | any {|x| $x == false }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-all-false"
        category: "globals"
        tags: [globals arrays bool all closure global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  (global-get flags) | all {|x| $x == false }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
