const VERIFIER_DIFF_FIXTURES_2394_2394 = [
    {
        name: "map-put-rejects-unknown-kind"
        category: "maps"
        tags: [maps map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen $ctx.pid --kind mystery-map-kind'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put --kind must name a recognized map family"
    }
]
