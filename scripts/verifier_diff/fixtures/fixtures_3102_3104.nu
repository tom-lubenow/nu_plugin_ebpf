const VERIFIER_DIFF_FIXTURES_3102_3104 = [
    {
        name: "global-define-rejects-binary-initializer-over-capacity"
        category: "globals"
        tags: [globals global-define diagnostics reject capacity binary]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | global-define --type bytes:2 buf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'bytes:2' initializer is 3 bytes but capacity is 2"
    }
    {
        name: "global-define-rejects-string-initializer-over-capacity"
        category: "globals"
        tags: [globals global-define diagnostics reject capacity string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcd" | global-define --type string:3 label'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'string:3' initializer is 4 bytes but capacity is 3"
    }
    {
        name: "global-define-rejects-list-initializer-over-capacity"
        category: "globals"
        tags: [globals global-define diagnostics reject capacity list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | global-define --type list:int:2 values'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'list:int:2' initializer has 3 items but capacity is 2"
    }
]
