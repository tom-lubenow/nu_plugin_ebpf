const VERIFIER_DIFF_FIXTURES_2437_2437 = [
    {
        name: "map-define-rejects-dynamic-name"
        category: "maps"
        tags: [maps map-define diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define $ctx.pid --kind hash --key-type u32 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define requires a compile-time string literal"
    }
]
