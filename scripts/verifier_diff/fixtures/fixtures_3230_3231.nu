export const VERIFIER_DIFF_FIXTURES_3230_3231 = [
    {
        name: "global-define-type-array-u32-uniq-math-sum"
        category: "globals"
        tags: [globals arrays u32 uniq math sum global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | uniq | math sum) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-uniq-math-product"
        category: "globals"
        tags: [globals arrays u32 uniq math product global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | uniq | math product) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
