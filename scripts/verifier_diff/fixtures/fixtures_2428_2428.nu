const VERIFIER_DIFF_FIXTURES_2428_2428 = [
    {
        name: "map-define-rejects-invalid-name"
        category: "maps"
        tags: [maps map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define "1bad" --kind hash --key-type u32 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define map name '1bad' must match [A-Za-z_][A-Za-z0-9_]*"
    }
]
