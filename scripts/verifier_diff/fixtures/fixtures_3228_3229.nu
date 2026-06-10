export const VERIFIER_DIFF_FIXTURES_3228_3229 = [
    {
        name: "global-define-type-array-u32-uniq-math-min"
        category: "globals"
        tags: [globals arrays u32 uniq math min global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | uniq | math min) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-uniq-math-max"
        category: "globals"
        tags: [globals arrays u32 uniq math max global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | uniq | math max) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
