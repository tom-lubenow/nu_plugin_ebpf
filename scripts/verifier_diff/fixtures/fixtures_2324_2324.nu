const VERIFIER_DIFF_FIXTURES_2324_2324 = [
    {
        name: "global-define-type-nested-record-duplicate-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{pid:u32,pid:u64}}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'inner.pid' is duplicated"
    }
]
