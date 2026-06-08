const VERIFIER_DIFF_FIXTURES_2326_2326 = [
    {
        name: "global-get-without-same-program-layout-rejects"
        category: "globals"
        tags: [globals diagnostics global-get reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-get state'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a same-program global-define or layout-establishing global-set"
    }
]
