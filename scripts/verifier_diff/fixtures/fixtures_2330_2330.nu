const VERIFIER_DIFF_FIXTURES_2330_2330 = [
    {
        name: "map-define-key-type-invalid-array-length-rejects-context"
        category: "maps"
        tags: [maps map-define arrays diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_keys --kind hash --key-type "array{u32:x}" --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map key type spec 'array{u32:x}' has an invalid array length"
    }
]
