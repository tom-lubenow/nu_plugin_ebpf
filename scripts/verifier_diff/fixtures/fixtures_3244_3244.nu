export const VERIFIER_DIFF_FIXTURES_3244_3244 = [
    {
        name: "global-define-type-array-i32-math-mode-length"
        category: "globals"
        tags: [globals arrays i32 math mode length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{i32:3}" ports'
            '  (((global-get ports) | math mode | length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
