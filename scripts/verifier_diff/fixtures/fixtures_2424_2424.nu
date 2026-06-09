const VERIFIER_DIFF_FIXTURES_2424_2424 = [
    {
        name: "map-define-signature-rejects-flags"
        category: "maps"
        tags: [maps map-define flags diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --zero --kind hash --key-type u32 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "doesn't have flag `zero`"
    }
]
