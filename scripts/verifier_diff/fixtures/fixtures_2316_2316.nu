const VERIFIER_DIFF_FIXTURES_2316_2316 = [
    {
        name: "global-typed-array-first-negative-count-rejects"
        category: "globals"
        tags: [globals arrays typed first reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  global-get ports | first -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first count must be non-negative"
    }
]
