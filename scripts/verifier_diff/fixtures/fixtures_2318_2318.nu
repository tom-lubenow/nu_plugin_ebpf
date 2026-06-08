const VERIFIER_DIFF_FIXTURES_2318_2318 = [
    {
        name: "global-typed-array-take-negative-count-rejects"
        category: "globals"
        tags: [globals arrays typed take reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  global-get ports | take -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "take count must be non-negative"
    }
]
