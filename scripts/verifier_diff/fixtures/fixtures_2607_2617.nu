const VERIFIER_DIFF_FIXTURES_2607_2617 = [
    {
        name: "core-math-round-precision-rejects-dynamic-precision"
        category: "language-core"
        tags: [math round precision diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1.234 | math round --precision $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math round requires a compile-time known integer precision in eBPF"
    }
    {
        name: "core-math-round-precision-rejects-unfolded-float-result"
        category: "language-core"
        tags: [math round precision diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1.234 | math round --precision 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math round --precision compile-time result has type float; eBPF supports only results folded by fill or str join"
    }
    {
        name: "core-math-abs-rejects-unfolded-float-result"
        category: "language-core"
        tags: [math abs diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1.5 | math abs'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math abs compile-time result has type float; eBPF supports only float results folded by fill or str join"
    }
    {
        name: "core-math-abs-rejects-unfolded-float-list-result"
        category: "language-core"
        tags: [math abs list diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [-1 2.5] | math abs'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math abs compile-time list result includes floats; eBPF supports only float results folded by fill or str join"
    }
    {
        name: "core-math-median-rejects-empty-list"
        category: "language-core"
        tags: [math median diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | math median'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math median requires a non-empty integer or float list in eBPF"
    }
    {
        name: "core-math-median-rejects-even-list-float-result"
        category: "language-core"
        tags: [math median diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | math median'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math median compile-time list median has type float; eBPF supports only integer median results unless folded by fill"
    }
    {
        name: "core-math-mode-rejects-dynamic-input"
        category: "language-core"
        tags: [math mode diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | math mode'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math mode requires compile-time known integer-list or stack-backed numeric-list input in eBPF"
    }
    {
        name: "core-math-arccos-rejects-out-of-domain-input"
        category: "language-core"
        tags: [math arccos diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  2 | math arccos'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arccos requires input in the closed interval [-1, 1] in eBPF; input is 2"
    }
    {
        name: "core-math-arctanh-rejects-out-of-domain-input"
        category: "language-core"
        tags: [math arctanh diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | math arctanh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arctanh requires input in the open interval (-1, 1) in eBPF; input is 1"
    }
    {
        name: "core-math-ln-rejects-non-positive-input"
        category: "language-core"
        tags: [math ln diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0 | math ln'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math ln requires positive input in eBPF; input is 0"
    }
    {
        name: "core-math-exp-rejects-unfolded-float-result"
        category: "language-core"
        tags: [math exp diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | math exp'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math exp compile-time result has type float; eBPF supports only results folded by fill or str join"
    }
]
