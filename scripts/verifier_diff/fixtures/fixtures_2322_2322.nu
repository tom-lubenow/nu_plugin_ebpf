const VERIFIER_DIFF_FIXTURES_2322_2322 = [
    {
        name: "global-define-type-string-initializer-exceeds-capacity-rejects"
        category: "globals"
        tags: [globals string global-define reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdef" | global-define --type "string:4" seen_name'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "capacity is 4"
    }
]
