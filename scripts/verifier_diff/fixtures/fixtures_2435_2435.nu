const VERIFIER_DIFF_FIXTURES_2435_2435 = [
    {
        name: "map-define-rejects-dynamic-value-type"
        category: "maps"
        tags: [maps map-define value-type diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind hash --key-type u32 --value-type $ctx.pid'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --value-type requires a compile-time string literal"
    }
]
