const VERIFIER_DIFF_FIXTURES_2419_2419 = [
    {
        name: "map-define-rejects-missing-value-type"
        category: "maps"
        tags: [maps map-define value-type diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind hash --key-type u32 --max-entries 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define requires --value-type with a compile-time type string"
    }
]
