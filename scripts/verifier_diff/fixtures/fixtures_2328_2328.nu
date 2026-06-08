const VERIFIER_DIFF_FIXTURES_2328_2328 = [
    {
        name: "map-define-value-type-zero-bytes-length-rejects-context"
        category: "maps"
        tags: [maps map-define binary diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_values --kind hash --value-type "bytes:0"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value type spec 'bytes:0' requires a positive byte-array length"
    }
]
