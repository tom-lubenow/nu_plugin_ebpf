export const VERIFIER_DIFF_FIXTURES_3253_3253 = [
    {
        name: "global-define-type-array-bool-compact-length"
        category: "globals"
        tags: [globals arrays bool compact length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bool:2}" flags'
            '  (((global-get flags) | compact | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
