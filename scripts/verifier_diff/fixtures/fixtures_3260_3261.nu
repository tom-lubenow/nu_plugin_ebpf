export const VERIFIER_DIFF_FIXTURES_3260_3261 = [
    {
        name: "global-define-type-array-u64-where-rejects-lossy-list"
        category: "globals"
        tags: [globals arrays u64 where diagnostics reject global-define]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (global-get ports) | where {|x| $x == 0 } | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "signed integer or <=32-bit unsigned integer scalar elements"
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
        error_contains: "signed integer or <=32-bit unsigned integer scalar elements"
    }
]
