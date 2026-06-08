const VERIFIER_DIFF_FIXTURES_2317_2317 = [
    {
        name: "global-typed-array-last-negative-count-rejects"
        category: "globals"
        tags: [globals arrays typed last reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  global-get ports | last -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last count must be non-negative"
    }
]
