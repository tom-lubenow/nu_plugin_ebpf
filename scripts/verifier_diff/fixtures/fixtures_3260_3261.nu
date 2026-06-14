export const VERIFIER_DIFF_FIXTURES_3260_3261 = [
    {
        name: "global-define-type-array-u64-where-length"
        category: "globals"
        tags: [globals arrays u64 where closure length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | where {|x| $x == 0 } | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-find-rejects-lossy-list"
        category: "globals"
        tags: [globals arrays u64 find diagnostics reject global-define]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (global-get ports) | find 0 | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "signed integer, bool, or <=32-bit unsigned integer scalar elements"
    }
]
