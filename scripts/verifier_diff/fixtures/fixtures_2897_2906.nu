const VERIFIER_DIFF_FIXTURES_2897_2906 = [
    {
        name: "core-math-sum-rejects-mixed-unit-list"
        category: "language-core"
        tags: [math sum diagnostics reject list unit]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1kb 2sec] | math sum'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sum requires homogeneous filesize or duration list items in eBPF; item 1 has type duration"
    }
    {
        name: "core-math-median-rejects-mixed-unit-list"
        category: "language-core"
        tags: [math median diagnostics reject list unit]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1kb 2sec] | math median'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math median requires homogeneous filesize or duration list items in eBPF; item 1 has type duration"
    }
    {
        name: "core-math-avg-rejects-mixed-unit-list"
        category: "language-core"
        tags: [math avg diagnostics reject list unit]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1kb 2sec] | math avg'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math avg requires homogeneous filesize or duration list items in eBPF; item 1 has type duration"
    }
    {
        name: "core-math-ceil-rejects-string-input"
        category: "language-core"
        tags: [math ceil diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | math ceil'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math ceil currently supports integer input only in eBPF"
    }
    {
        name: "core-math-floor-rejects-string-input"
        category: "language-core"
        tags: [math floor diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | math floor'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math floor currently supports integer input only in eBPF"
    }
    {
        name: "core-math-round-rejects-string-input"
        category: "language-core"
        tags: [math round diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | math round'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math round currently supports integer input only in eBPF"
    }
    {
        name: "core-math-round-precision-rejects-float-list-result"
        category: "language-core"
        tags: [math round precision diagnostics reject list result]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1.23] | math round --precision 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math round --precision compile-time result has type list<float>; eBPF supports only results folded by fill or str join"
    }
    {
        name: "core-math-arccos-rejects-dynamic-input"
        category: "language-core"
        tags: [math arccos diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | math arccos'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arccos requires compile-time known integer or float input in eBPF"
    }
    {
        name: "core-math-arccosh-rejects-dynamic-input"
        category: "language-core"
        tags: [math arccosh diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | math arccosh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arccosh requires compile-time known integer or float input in eBPF"
    }
    {
        name: "core-math-sinh-rejects-non-finite-list-result"
        category: "language-core"
        tags: [math sinh diagnostics reject list result finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1000] | math sinh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sinh list item 0 result must be finite in eBPF"
    }
]
