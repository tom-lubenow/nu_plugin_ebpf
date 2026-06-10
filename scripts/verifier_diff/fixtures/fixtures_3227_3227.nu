export const VERIFIER_DIFF_FIXTURES_3227_3227 = [
    {
        name: "global-define-type-array-u32-uniq-last"
        category: "globals"
        tags: [globals arrays u32 uniq last global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | uniq | last) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
