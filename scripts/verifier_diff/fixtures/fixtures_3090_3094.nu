const VERIFIER_DIFF_FIXTURES_3090_3094 = [
    {
        name: "core-math-abs-rejects-non-finite-list-item"
        category: "language-core"
        tags: [math abs diagnostics reject list float finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1e999] | math abs | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math abs requires finite float list items in eBPF; item 0 is inf"
    }
    {
        name: "core-math-avg-rejects-non-finite-list-item"
        category: "language-core"
        tags: [math avg diagnostics reject list float finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1e999] | math avg | fill --alignment right --character "0" --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math avg requires finite float list items in eBPF; item 0 is inf"
    }
    {
        name: "core-math-variance-rejects-non-finite-list-item"
        category: "language-core"
        tags: [math variance diagnostics reject list float finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1e999] | math variance | fill --alignment right --character "0" --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math variance requires finite float list items in eBPF; item 0 is inf"
    }
    {
        name: "core-math-stddev-rejects-non-finite-list-item"
        category: "language-core"
        tags: [math stddev diagnostics reject list float finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1e999] | math stddev | fill --alignment right --character "0" --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math stddev requires finite float list items in eBPF; item 0 is inf"
    }
    {
        name: "core-math-median-rejects-non-finite-list-item"
        category: "language-core"
        tags: [math median diagnostics reject list float finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1e999] | math median | fill --alignment right --character "0" --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math median requires finite float list items in eBPF; item 0 is inf"
    }
]
