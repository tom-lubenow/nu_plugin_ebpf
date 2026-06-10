export const VERIFIER_DIFF_FIXTURES_3242_3242 = [
    {
        name: "global-define-type-array-i32-math-abs-sum"
        category: "globals"
        tags: [globals arrays i32 math abs sum global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{i32:2}" ports'
            '  (((global-get ports) | math abs | math sum) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
