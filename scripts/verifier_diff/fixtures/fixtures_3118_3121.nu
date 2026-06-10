const VERIFIER_DIFF_FIXTURES_3118_3121 = [
    {
        name: "global-define-rejects-fixed-array-initializer-over-length"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer array]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | global-define --type "array{u32:2}" arr'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'array{u32:2}' initializer has 3 items but length is 2"
    }
    {
        name: "global-define-rejects-fixed-array-initializer-item-type-mismatch"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer array]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | global-define --type "array{u32:2}" arr'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'array{u32:2}' initializer[1] requires a u32-compatible constant"
    }
    {
        name: "global-define-rejects-record-initializer-type-mismatch"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer record]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | global-define --type "record{count:u32}" rec'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'record{count:u32}' initializer requires a record constant"
    }
    {
        name: "global-define-rejects-record-initializer-unexpected-field"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer record]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {count: 1 extra: 2} | global-define --type "record{count:u32}" rec'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'record{count:u32}' initializer contains unexpected field 'extra'"
    }
]
