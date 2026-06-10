export const VERIFIER_DIFF_FIXTURES_3224_3225 = [
    {
        name: "global-define-type-array-u32-uniq-length"
        category: "globals"
        tags: [globals arrays u32 uniq length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | uniq | length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-i32-uniq-length"
        category: "globals"
        tags: [globals arrays i32 uniq length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{i32:2}" ports'
            '  (((global-get ports) | uniq | length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
