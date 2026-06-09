const VERIFIER_DIFF_FIXTURES_2421_2421 = [
    {
        name: "map-define-rejects-overflow-max-entries"
        category: "maps"
        tags: [maps map-define max-entries diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind hash --key-type u32 --value-type u64 --max-entries 4294967296'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --max-entries must fit in u32"
    }
]
