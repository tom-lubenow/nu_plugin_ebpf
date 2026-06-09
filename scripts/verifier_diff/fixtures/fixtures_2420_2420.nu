const VERIFIER_DIFF_FIXTURES_2420_2420 = [
    {
        name: "map-define-rejects-zero-max-entries"
        category: "maps"
        tags: [maps map-define max-entries diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind hash --key-type u32 --value-type u64 --max-entries 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --max-entries must be positive"
    }
]
