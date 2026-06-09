const VERIFIER_DIFF_FIXTURES_3086_3089 = [
    {
        name: "core-math-variance-rejects-unfolded-float-result"
        category: "language-core"
        tags: [math variance diagnostics reject list float]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | math variance'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math variance compile-time list result has type float; eBPF supports only results folded by fill"
    }
    {
        name: "core-math-stddev-rejects-unfolded-float-result"
        category: "language-core"
        tags: [math stddev diagnostics reject list float]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | math stddev'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math stddev compile-time list result has type float; eBPF supports only results folded by fill"
    }
    {
        name: "core-math-variance-rejects-non-finite-result"
        category: "language-core"
        tags: [math variance diagnostics reject list float finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1e308 -1e308] | math variance | fill --alignment right --character "0" --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math variance compile-time list result must be finite in eBPF"
    }
    {
        name: "core-math-stddev-rejects-non-finite-result"
        category: "language-core"
        tags: [math stddev diagnostics reject list float finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1e308 -1e308] | math stddev | fill --alignment right --character "0" --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math stddev compile-time list result must be finite in eBPF"
    }
]
