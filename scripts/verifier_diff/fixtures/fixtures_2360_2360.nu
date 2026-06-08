const VERIFIER_DIFF_FIXTURES_2360_2360 = [
    {
        name: "array-of-maps-map-put-rejects-outer-kind"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put outer_array $ctx.pid --kind array-of-maps'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put is not supported for map-in-map outer map"
    }
]
