const VERIFIER_DIFF_FIXTURES_2331_2331 = [
    {
        name: "map-define-key-type-empty-record-rejects-context"
        category: "maps"
        tags: [maps map-define records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define empty_key --kind hash --key-type "record{}" --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map key type spec 'record{}' requires at least one record field"
    }
]
