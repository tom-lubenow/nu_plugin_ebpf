const VERIFIER_DIFF_FIXTURES_2429_2429 = [
    {
        name: "map-define-inner-map-rejects-invalid-name"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define outer_array --kind array-of-maps --inner-map "1bad" --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --inner-map map name '1bad' must match [A-Za-z_][A-Za-z0-9_]*"
    }
]
