const VERIFIER_DIFF_FIXTURES_2379_2379 = [
    {
        name: "hash-of-maps-map-delete-rejects-outer-kind"
        category: "maps"
        tags: [maps map-in-map hash-of-maps map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete outer_hash --kind hash-of-maps'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete is not supported for map-in-map outer map"
    }
]
