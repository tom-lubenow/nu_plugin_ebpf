const VERIFIER_DIFF_FIXTURES_3114_3117 = [
    {
        name: "global-define-rejects-i8-initializer-overflow"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer numeric overflow]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  200 | global-define --type i8 small'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'i8' initializer does not fit in i8"
    }
    {
        name: "global-define-rejects-u8-initializer-underflow"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer numeric overflow]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  -1 | global-define --type u8 small'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'u8' initializer does not fit in u8"
    }
    {
        name: "global-define-rejects-string-initializer-type-mismatch"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | global-define --type string:4 label'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'string:4' initializer requires a string or glob constant"
    }
    {
        name: "global-define-rejects-fixed-array-initializer-type-mismatch"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer array]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | global-define --type "array{u32:2}" arr'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'array{u32:2}' initializer requires a constant list"
    }
]
