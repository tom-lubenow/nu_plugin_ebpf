const VERIFIER_DIFF_FIXTURES_2400_2400 = [
    {
        name: "map-define-rejects-dynamic-kind"
        category: "maps"
        tags: [maps map-define diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind $ctx.pid'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind requires a compile-time string literal"
    }
]
