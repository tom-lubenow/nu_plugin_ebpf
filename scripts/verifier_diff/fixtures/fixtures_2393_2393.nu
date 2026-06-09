const VERIFIER_DIFF_FIXTURES_2393_2393 = [
    {
        name: "map-get-rejects-dynamic-kind"
        category: "maps"
        tags: [maps map-get diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = (0 | map-get seen --kind $ctx.pid)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --kind requires a compile-time string literal"
    }
]
