const VERIFIER_DIFF_FIXTURES_2425_2425 = [
    {
        name: "map-define-signature-rejects-missing-name"
        category: "maps"
        tags: [maps map-define signature diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define --kind hash --key-type u32 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "missing name"
    }
]
