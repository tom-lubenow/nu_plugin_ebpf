export const VERIFIER_DIFF_FIXTURES_3234_3235 = [
    {
        name: "global-define-type-array-u32-any-zero"
        category: "globals"
        tags: [globals arrays u32 any closure global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (global-get ports) | any {|x| $x == 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-all-zero"
        category: "globals"
        tags: [globals arrays u32 all closure global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (global-get ports) | all {|x| $x == 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
