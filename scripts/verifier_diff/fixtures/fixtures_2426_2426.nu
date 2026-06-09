const VERIFIER_DIFF_FIXTURES_2426_2426 = [
    {
        name: "map-define-signature-rejects-extra-name"
        category: "maps"
        tags: [maps map-define signature diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen extra --kind hash --key-type u32 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Extra positional argument"
    }
]
