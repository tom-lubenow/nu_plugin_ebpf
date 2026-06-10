const VERIFIER_DIFF_FIXTURES_3125_3130 = [
    {
        name: "core-seq-date-input-format-dynamic-reject"
        category: "language-core"
        tags: [seq date diagnostics reject input-format dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --input-format $ctx.comm --begin-date "2020-01-01" --end-date "2020-01-02" | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --input-format requires a compile-time string literal"
    }
    {
        name: "core-seq-date-output-format-dynamic-reject"
        category: "language-core"
        tags: [seq date diagnostics reject output-format dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --output-format $ctx.comm --begin-date "2020-01-01" --end-date "2020-01-02" | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --output-format requires a compile-time string literal"
    }
    {
        name: "core-seq-date-begin-date-dynamic-reject"
        category: "language-core"
        tags: [seq date diagnostics reject begin-date dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date $ctx.comm --end-date "2020-01-02" | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --begin-date requires a compile-time string literal"
    }
    {
        name: "core-seq-date-end-date-dynamic-reject"
        category: "language-core"
        tags: [seq date diagnostics reject end-date dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date $ctx.comm | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --end-date requires a compile-time string literal"
    }
    {
        name: "core-seq-date-periods-dynamic-reject"
        category: "language-core"
        tags: [seq date diagnostics reject periods dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods $ctx.pid | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --periods requires a compile-time known integer in eBPF"
    }
    {
        name: "core-seq-date-periods-zero-reject"
        category: "language-core"
        tags: [seq date diagnostics reject periods bounds]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 0 | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --periods requires a positive integer in eBPF"
    }
]
