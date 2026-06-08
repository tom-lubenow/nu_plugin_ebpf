const VERIFIER_DIFF_FIXTURES_2378_2378 = [
    {
        name: "array-of-maps-map-delete-rejects-outer-kind"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete outer_array --kind array-of-maps'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete is not supported for map-in-map outer map"
    }
]
