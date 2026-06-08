const VERIFIER_DIFF_FIXTURES_2320_2320 = [
    {
        name: "global-typed-array-drop-negative-count-rejects"
        category: "globals"
        tags: [globals arrays typed drop reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  global-get ports | drop -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "drop count must be non-negative"
    }
]
