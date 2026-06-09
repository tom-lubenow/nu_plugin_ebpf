const VERIFIER_DIFF_FIXTURES_2416_2416 = [
    {
        name: "map-define-inner-map-rejects-non-outer-kind"
        category: "maps"
        tags: [maps map-in-map map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define plain_hash --kind hash --inner-map inner_seen'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --inner-map is only supported for array-of-maps or hash-of-maps"
    }
]
