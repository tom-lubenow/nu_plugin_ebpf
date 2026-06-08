const VERIFIER_DIFF_FIXTURES_2361_2361 = [
    {
        name: "hash-of-maps-map-put-rejects-outer-kind"
        category: "maps"
        tags: [maps map-in-map hash-of-maps map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put outer_hash $ctx.pid --kind hash-of-maps'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put is not supported for map-in-map outer map"
    }
]
