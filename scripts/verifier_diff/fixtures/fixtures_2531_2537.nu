const VERIFIER_DIFF_FIXTURES_2531_2537 = [
    {
        name: "core-string-str-stats-rejects-dynamic-input"
        category: "language-core"
        tags: [string str stats diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str stats'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str stats requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-str-expand-rejects-dynamic-input"
        category: "language-core"
        tags: [string str expand diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str expand'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str expand requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-str-expand-rejects-missing-braces"
        category: "language-core"
        tags: [string str expand diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str expand'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str expand requires at least one brace expression in eBPF"
    }
    {
        name: "core-string-str-expand-rejects-unbalanced-braces"
        category: "language-core"
        tags: [string str expand diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c" | str expand'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str expand requires balanced brace expressions in eBPF"
    }
    {
        name: "core-string-str-expand-rejects-multiple-range-operators"
        category: "language-core"
        tags: [string str expand diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{1..2..3}" | str expand'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str expand numeric ranges must use exactly one '..' operator in eBPF"
    }
    {
        name: "core-string-str-expand-rejects-signed-range-bound"
        category: "language-core"
        tags: [string str expand diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{-1..3}" | str expand'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str expand numeric ranges must use unsigned integer bounds in eBPF"
    }
    {
        name: "core-string-str-expand-rejects-large-range"
        category: "language-core"
        tags: [string str expand diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{1..61}" | str expand'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str expand range produces 61 strings; eBPF lowering supports at most 60"
    }
]
