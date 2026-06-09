const VERIFIER_DIFF_FIXTURES_2434_2434 = [
    {
        name: "map-define-rejects-dynamic-key-type"
        category: "maps"
        tags: [maps map-define key-type diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind hash --key-type $ctx.pid --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --key-type requires a compile-time string literal"
    }
]
