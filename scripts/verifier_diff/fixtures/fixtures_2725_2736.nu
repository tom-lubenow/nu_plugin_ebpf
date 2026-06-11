const VERIFIER_DIFF_FIXTURES_2725_2736 = [
    {
        name: "core-math-round-precision-rejects-missing-input"
        category: "language-core"
        tags: [math round precision diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  math round --precision 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math round requires compile-time known integer or float input with --precision in eBPF"
    }
    {
        name: "core-math-log-rejects-dynamic-base"
        category: "language-core"
        tags: [math log diagnostics reject base dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  8 | math log $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log requires a compile-time known integer or float base in eBPF"
    }
    {
        name: "core-math-log-rejects-dynamic-input"
        category: "language-core"
        tags: [math log diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | math log 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log requires compile-time known integer or float input in eBPF"
    }
    {
        name: "core-math-log-rejects-missing-input"
        category: "language-core"
        tags: [math log diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  math log 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log requires compile-time known integer or float input in eBPF"
    }
    {
        name: "core-math-log-rejects-zero-base"
        category: "language-core"
        tags: [math log diagnostics reject base]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  8 | math log 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log base must be positive and not 1 in eBPF; base is 0"
    }
    {
        name: "core-math-log-rejects-zero-input"
        category: "language-core"
        tags: [math log diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0 | math log 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log requires positive input in eBPF; input is 0"
    }
    {
        name: "core-math-log-rejects-negative-list-item"
        category: "language-core"
        tags: [math log diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [-1 8] | math log 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log requires positive list items in eBPF; item 0 is -1"
    }
    {
        name: "core-math-abs-rejects-missing-input"
        category: "language-core"
        tags: [math abs diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  math abs'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math abs requires integer, integer-list, or stack-backed numeric-list input in eBPF"
    }
    {
        name: "core-math-abs-rejects-string-input"
        category: "language-core"
        tags: [math abs diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | math abs'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Command does not support string input"
    }
    {
        name: "core-math-median-rejects-missing-input"
        category: "language-core"
        tags: [math median diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  math median'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math median requires compile-time known integer-list or integer/float-list input in eBPF"
    }
    {
        name: "core-math-median-rejects-string-input"
        category: "language-core"
        tags: [math median diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | math median'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Command does not support string input"
    }
    {
        name: "core-math-product-rejects-missing-input"
        category: "language-core"
        tags: [math product diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  math product'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math product requires a stack-backed numeric list input in eBPF"
    }
]
