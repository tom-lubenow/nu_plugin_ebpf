const VERIFIER_DIFF_FIXTURES_3105_3107 = [
    {
        name: "global-define-rejects-empty-record-type"
        category: "globals"
        tags: [globals global-define diagnostics reject record shape]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type record{} empty'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record global declarations require at least one field"
    }
    {
        name: "global-define-rejects-zero-length-fixed-array"
        category: "globals"
        tags: [globals global-define diagnostics reject array shape]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:0}" arr'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global fixed-array declarations require a positive length"
    }
    {
        name: "global-define-rejects-zero-length-byte-array"
        category: "globals"
        tags: [globals global-define diagnostics reject binary shape]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type bytes:0 buf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global byte-array declarations require a positive length"
    }
]
