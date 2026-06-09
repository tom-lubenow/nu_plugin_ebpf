const VERIFIER_DIFF_FIXTURES_2427_2427 = [
    {
        name: "map-define-rejects-empty-name"
        category: "maps"
        tags: [maps map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define "" --kind hash --key-type u32 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define map name must not be empty"
    }
]
