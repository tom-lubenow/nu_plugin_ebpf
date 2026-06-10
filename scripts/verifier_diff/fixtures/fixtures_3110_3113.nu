const VERIFIER_DIFF_FIXTURES_3110_3113 = [
    {
        name: "global-define-rejects-numeric-initializer-type-mismatch"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer numeric]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "x" | global-define --type u8 count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'u8' initializer requires a u8-compatible constant"
    }
    {
        name: "global-define-rejects-bool-initializer-type-mismatch"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer bool]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | global-define --type bool flag'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'bool' initializer requires a bool constant"
    }
    {
        name: "global-define-rejects-binary-initializer-type-mismatch"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer binary]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | global-define --type bytes:4 buf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'bytes:4' initializer requires a binary constant"
    }
    {
        name: "global-define-rejects-numeric-list-initializer-item-type-mismatch"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | global-define --type list:int:4 vals'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'list:int:4' initializer[1] requires a numeric constant item, found string"
    }
]
