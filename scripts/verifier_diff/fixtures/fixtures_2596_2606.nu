const VERIFIER_DIFF_FIXTURES_2596_2606 = [
    {
        name: "core-math-avg-rejects-empty-list"
        category: "language-core"
        tags: [math avg diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | math avg'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math avg requires a non-empty numeric list in eBPF"
    }
    {
        name: "core-math-avg-rejects-scalar-input"
        category: "language-core"
        tags: [math avg diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | math avg'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math avg requires a compile-time known numeric list in eBPF; input has type int"
    }
    {
        name: "core-math-avg-rejects-dynamic-input"
        category: "language-core"
        tags: [math avg diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | math avg'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math avg requires a compile-time known numeric list in eBPF"
    }
    {
        name: "core-math-avg-rejects-unfolded-float-result"
        category: "language-core"
        tags: [math avg diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | math avg'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math avg compile-time list result has type float; eBPF supports only average results folded by fill"
    }
    {
        name: "core-math-variance-rejects-empty-list"
        category: "language-core"
        tags: [math variance diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | math variance'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math variance requires a non-empty numeric list in eBPF"
    }
    {
        name: "core-math-variance-rejects-sample-singleton"
        category: "language-core"
        tags: [math variance sample diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1] | math variance --sample'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math variance --sample requires at least two numeric list items in eBPF"
    }
    {
        name: "core-math-log-rejects-base-one"
        category: "language-core"
        tags: [math log diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  8 | math log 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log base must be positive and not 1 in eBPF; base is 1"
    }
    {
        name: "core-math-log-rejects-negative-input"
        category: "language-core"
        tags: [math log diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  -8 | math log 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log requires positive input in eBPF; input is -8"
    }
    {
        name: "core-math-log-rejects-unfolded-float-result"
        category: "language-core"
        tags: [math log diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  8 | math log 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log compile-time result has type float; eBPF supports only results folded by fill or str join"
    }
    {
        name: "core-math-sqrt-rejects-negative-input"
        category: "language-core"
        tags: [math sqrt diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  -1 | math sqrt'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sqrt requires non-negative input in eBPF; input is -1"
    }
    {
        name: "core-math-sqrt-rejects-unfolded-float-result"
        category: "language-core"
        tags: [math sqrt diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  4 | math sqrt'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sqrt compile-time result has type float; eBPF supports only results folded by fill or str join"
    }
]
