const VERIFIER_DIFF_FIXTURES_2348_2348 = [
    {
        name: "map-define-key-type-record-empty-rejects-field"
        category: "maps"
        tags: [maps map-define key-type records diagnostics reject]
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
