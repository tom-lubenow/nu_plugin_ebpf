const VERIFIER_DIFF_FIXTURES_2329_2329 = [
    {
        name: "map-define-key-type-zero-bytes-length-rejects-context"
        category: "maps"
        tags: [maps map-define binary diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_keys --kind hash --key-type "bytes:0" --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map key type spec 'bytes:0' requires a positive byte-array length"
    }
]
