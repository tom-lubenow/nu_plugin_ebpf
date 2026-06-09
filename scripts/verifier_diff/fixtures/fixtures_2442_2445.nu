const VERIFIER_DIFF_FIXTURES_2442_2445 = [
    {
        name: "core-binary-bytes-index-of-rejects-dynamic-pattern"
        category: "language-core"
        tags: [binary bytes index-of diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes index-of $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes index-of requires a compile-time known binary pattern in eBPF"
    }
    {
        name: "core-binary-bytes-index-of-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes index-of diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 1] | bytes index-of 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes index-of requires binary list items in eBPF; item 1 has type int"
    }
    {
        name: "core-binary-bytes-index-of-rejects-empty-pattern"
        category: "language-core"
        tags: [binary bytes index-of diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes index-of 0x[]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes index-of requires a non-empty binary pattern in eBPF"
    }
    {
        name: "core-binary-bytes-index-of-rejects-dynamic-input"
        category: "language-core"
        tags: [binary bytes index-of diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | bytes index-of 0x[02]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes index-of requires compile-time known binary or list<binary> input in eBPF"
    }
]
