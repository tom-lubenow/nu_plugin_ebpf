export const VERIFIER_DIFF_FIXTURES_3243_3243 = [
    {
        name: "global-define-type-array-i32-math-median"
        category: "globals"
        tags: [globals arrays i32 math median global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{i32:3}" ports'
            '  (((global-get ports) | math median) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
