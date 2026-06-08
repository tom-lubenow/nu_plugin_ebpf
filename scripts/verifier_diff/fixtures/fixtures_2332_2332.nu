const VERIFIER_DIFF_FIXTURES_2332_2332 = [
    {
        name: "map-define-value-type-reserved-record-field-rejects-path"
        category: "maps"
        tags: [maps map-define records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_values --kind hash --value-type "record{__layout_pad0:u32}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field '__layout_pad0' uses reserved prefix '__layout_pad'"
    }
]
