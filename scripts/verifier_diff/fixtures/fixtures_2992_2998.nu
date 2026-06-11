const VERIFIER_DIFF_FIXTURES_2992_2998 = [
    {
        name: "core-list-first-strict-count"
        category: "language-core"
        tags: [list first strict accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | first --strict 1 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-first-rejects-negative-count"
        category: "language-core"
        tags: [list first diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | first -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first count must be non-negative in eBPF"
    }
    {
        name: "core-list-last-strict-count"
        category: "language-core"
        tags: [list last strict accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | last --strict 1 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-last-rejects-negative-count"
        category: "language-core"
        tags: [list last diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | last -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last count must be non-negative in eBPF"
    }
    {
        name: "core-list-skip-rejects-negative-count"
        category: "language-core"
        tags: [list skip diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | skip -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skip count must be non-negative in eBPF"
    }
    {
        name: "core-list-drop-rejects-negative-count"
        category: "language-core"
        tags: [list drop diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | drop -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "drop count must be non-negative in eBPF"
    }
    {
        name: "core-list-take-rejects-negative-count"
        category: "language-core"
        tags: [list take diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | take -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "take count must be non-negative in eBPF"
    }
]
