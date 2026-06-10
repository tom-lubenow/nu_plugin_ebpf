export const VERIFIER_DIFF_FIXTURES_3256_3257 = [
    {
        name: "global-define-type-array-u64-any-zero"
        category: "globals"
        tags: [globals arrays u64 any closure global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (global-get ports) | any {|x| $x == 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-all-zero"
        category: "globals"
        tags: [globals arrays u64 all closure global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (global-get ports) | all {|x| $x == 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
