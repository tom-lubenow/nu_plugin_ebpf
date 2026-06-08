const VERIFIER_DIFF_FIXTURES_2325_2325 = [
    {
        name: "global-define-type-record-reserved-padding-field-rejects"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{a:u8,__layout_pad0:u64}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record type specs reserve field names starting with '__layout_pad'"
    }
]
