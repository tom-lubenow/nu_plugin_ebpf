const VERIFIER_DIFF_FIXTURES_0313_0343_A = [
    {
        name: "global-define-type-nested-record-malformed-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{bad}}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'inner.bad' must use name:type syntax"
    }
    {
        name: "global-define-type-nested-record-invalid-array-length-rejects-path"
        category: "globals"
        tags: [globals records arrays diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{items:array{u32:x}}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'items' type spec 'array{u32:x}' has an invalid array length"
    }
    {
        name: "global-define-type-record-unmatched-braces-rejects-candidate"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{pid:u32" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'record{inner:record{pid:u32' has unmatched '{' braces"
    }
]
