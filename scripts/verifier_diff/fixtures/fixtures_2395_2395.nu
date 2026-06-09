const VERIFIER_DIFF_FIXTURES_2395_2395 = [
    {
        name: "map-put-rejects-dynamic-kind"
        category: "maps"
        tags: [maps map-put diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen $ctx.pid --kind $ctx.pid'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put --kind requires a compile-time string literal"
    }
]
