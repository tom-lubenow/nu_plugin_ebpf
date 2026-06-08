const VERIFIER_DIFF_FIXTURES_2323_2323 = [
    {
        name: "global-define-type-nested-record-unsupported-type-rejects-path"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:bogus}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unsupported record field 'inner' type spec 'bogus'"
    }
]
