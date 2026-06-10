const VERIFIER_DIFF_FIXTURES_3100_3101 = [
    {
        name: "global-define-rejects-oversized-string-capacity"
        category: "globals"
        tags: [globals global-define diagnostics reject capacity string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:128 too_big'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global string declarations require a capacity between 1 and 127"
    }
    {
        name: "global-define-rejects-oversized-numeric-list-capacity"
        category: "globals"
        tags: [globals global-define diagnostics reject capacity list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type list:int:61 values'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global numeric list declarations require a capacity of at most 60"
    }
]
