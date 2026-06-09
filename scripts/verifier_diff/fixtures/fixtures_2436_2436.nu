const VERIFIER_DIFF_FIXTURES_2436_2436 = [
    {
        name: "map-define-inner-map-rejects-dynamic-name"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-define diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define outer_array --kind array-of-maps --inner-map $ctx.pid --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --inner-map requires a compile-time string literal"
    }
]
