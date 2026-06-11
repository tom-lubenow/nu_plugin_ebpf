const VERIFIER_DIFF_FIXTURES_2887_2896 = [
    {
        name: "core-math-arcsin-rejects-out-of-domain-list-item"
        category: "language-core"
        tags: [math arcsin diagnostics reject list domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [2] | math arcsin'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arcsin requires list items in the closed interval [-1, 1] in eBPF; item 0 is 2"
    }
    {
        name: "core-math-arctanh-rejects-out-of-domain-list-item"
        category: "language-core"
        tags: [math arctanh diagnostics reject list domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1] | math arctanh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arctanh requires list items in the open interval (-1, 1) in eBPF; item 0 is 1"
    }
    {
        name: "core-math-ln-rejects-non-positive-list-item"
        category: "language-core"
        tags: [math ln diagnostics reject list domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0] | math ln'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math ln requires positive list items in eBPF; item 0 is 0"
    }
    {
        name: "core-math-log-rejects-non-positive-list-item"
        category: "language-core"
        tags: [math log diagnostics reject list domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0 8] | math log 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math log requires positive list items in eBPF; item 0 is 0"
    }
    {
        name: "core-math-arcsin-rejects-dynamic-input"
        category: "language-core"
        tags: [math arcsin diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | math arcsin'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arcsin requires compile-time known integer or float input in eBPF"
    }
    {
        name: "core-math-exp-rejects-non-finite-result"
        category: "language-core"
        tags: [math exp diagnostics reject result finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1000 | math exp'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math exp result must be finite in eBPF"
    }
    {
        name: "core-math-cosh-rejects-non-finite-result"
        category: "language-core"
        tags: [math cosh diagnostics reject result finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1000 | math cosh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math cosh result must be finite in eBPF"
    }
    {
        name: "core-math-sinh-rejects-non-finite-result"
        category: "language-core"
        tags: [math sinh diagnostics reject result finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1000 | math sinh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sinh result must be finite in eBPF"
    }
    {
        name: "core-math-exp-rejects-non-finite-list-result"
        category: "language-core"
        tags: [math exp diagnostics reject list result finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1000] | math exp'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math exp list item 0 result must be finite in eBPF"
    }
    {
        name: "core-math-cosh-rejects-non-finite-list-result"
        category: "language-core"
        tags: [math cosh diagnostics reject list result finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1000] | math cosh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math cosh list item 0 result must be finite in eBPF"
    }
]
