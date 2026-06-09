const VERIFIER_DIFF_FIXTURES_2398_2398 = [
    {
        name: "map-contains-rejects-dynamic-kind"
        category: "maps"
        tags: [maps map-contains diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-contains seen 0 --kind $ctx.pid'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-contains --kind requires a compile-time string literal"
    }
]
