const VERIFIER_DIFF_FIXTURES_2391_2391 = [
    {
        name: "map-delete-rejects-dynamic-kind"
        category: "maps"
        tags: [maps map-delete diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete seen --kind $ctx.pid'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind requires a compile-time string literal"
    }
]
