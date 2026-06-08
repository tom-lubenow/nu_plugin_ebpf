const VERIFIER_DIFF_FIXTURES_2327_2327 = [
    {
        name: "global-set-conflicting-layouts-rejects"
        category: "globals"
        tags: [globals diagnostics global-set reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  7 | global-set state'
            '  "oops" | global-set state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global 'state' is used with incompatible layouts"
    }
]
