const VERIFIER_DIFF_FIXTURES_2651_2661 = [
    {
        name: "core-global-define-rejects-dynamic-name"
        category: "globals"
        tags: [globals global-define diagnostics reject dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | global-define $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define requires a compile-time string literal"
    }
    {
        name: "core-global-define-rejects-invalid-name"
        category: "globals"
        tags: [globals global-define diagnostics reject name]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | global-define "1bad"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define map name '1bad' must match [A-Za-z_][A-Za-z0-9_]*"
    }
    {
        name: "core-global-define-zero-rejects-missing-pipeline"
        category: "globals"
        tags: [globals global-define zero diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --zero state'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define --zero requires a value from pipeline input to establish layout"
    }
    {
        name: "core-global-define-type-rejects-zero-flag"
        category: "globals"
        tags: [globals global-define typed zero diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type int --zero state'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define --type already implies zero initialization; do not combine it with --zero"
    }
    {
        name: "core-global-define-type-rejects-dynamic-type"
        category: "globals"
        tags: [globals global-define typed diagnostics reject dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type $ctx.comm state'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define --type requires a compile-time string literal"
    }
    {
        name: "core-global-define-type-rejects-runtime-initializer"
        category: "globals"
        tags: [globals global-define typed diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | global-define --type int state'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define --type with pipeline input requires a compile-time constant value"
    }
    {
        name: "core-global-define-rejects-runtime-initializer"
        category: "globals"
        tags: [globals global-define diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | global-define state'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define requires a compile-time constant value"
    }
    {
        name: "core-global-get-rejects-dynamic-name"
        category: "globals"
        tags: [globals global-get diagnostics reject dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-get $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-get requires a compile-time string literal"
    }
    {
        name: "core-global-get-rejects-invalid-name"
        category: "globals"
        tags: [globals global-get diagnostics reject name]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-get "1bad"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-get map name '1bad' must match [A-Za-z_][A-Za-z0-9_]*"
    }
    {
        name: "core-global-set-rejects-dynamic-name"
        category: "globals"
        tags: [globals global-set diagnostics reject dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | global-set $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-set requires a compile-time string literal"
    }
    {
        name: "core-global-set-rejects-invalid-name"
        category: "globals"
        tags: [globals global-set diagnostics reject name]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | global-set "1bad"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-set map name '1bad' must match [A-Za-z_][A-Za-z0-9_]*"
    }
]
