export const VERIFIER_DIFF_FIXTURES_3226_3226 = [
    {
        name: "global-define-type-array-u32-uniq-first"
        category: "globals"
        tags: [globals arrays u32 uniq first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | uniq | first) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
