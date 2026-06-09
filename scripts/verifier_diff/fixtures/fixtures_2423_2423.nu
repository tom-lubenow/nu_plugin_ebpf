const VERIFIER_DIFF_FIXTURES_2423_2423 = [
    {
        name: "map-define-rejects-dynamic-max-entries"
        category: "maps"
        tags: [maps map-define max-entries diagnostics reject dynamic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind hash --key-type u32 --value-type u64 --max-entries $ctx.pid'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --max-entries must be a compile-time integer literal"
    }
]
