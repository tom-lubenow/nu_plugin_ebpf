const VERIFIER_DIFF_FIXTURES_2333_2333 = [
    {
        name: "map-define-key-type-reserved-record-field-rejects-path"
        category: "maps"
        tags: [maps map-define records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_keys --kind hash --key-type "record{__layout_pad0:u32}" --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field '__layout_pad0' uses reserved prefix '__layout_pad'"
    }
]
