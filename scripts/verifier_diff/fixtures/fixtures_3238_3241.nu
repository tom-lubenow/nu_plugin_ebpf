export const VERIFIER_DIFF_FIXTURES_3238_3241 = [
    {
        name: "global-define-type-array-u32-math-min"
        category: "globals"
        tags: [globals arrays u32 math min global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | math min) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-math-max"
        category: "globals"
        tags: [globals arrays u32 math max global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | math max) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-math-sum"
        category: "globals"
        tags: [globals arrays u32 math sum global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | math sum) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-math-product"
        category: "globals"
        tags: [globals arrays u32 math product global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | math product) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
