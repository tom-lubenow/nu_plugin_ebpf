const VERIFIER_DIFF_FIXTURES_2319_2319 = [
    {
        name: "global-typed-array-skip-negative-count-rejects"
        category: "globals"
        tags: [globals arrays typed skip reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  global-get ports | skip -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skip count must be non-negative"
    }
]
