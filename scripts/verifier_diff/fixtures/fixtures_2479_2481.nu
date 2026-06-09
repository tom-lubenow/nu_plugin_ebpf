const VERIFIER_DIFF_FIXTURES_2479_2481 = [
    {
        name: "core-binary-bytes-collect-rejects-dynamic-input"
        category: "language-core"
        tags: [binary bytes collect diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes collect'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes collect requires compile-time known list<binary> input in eBPF"
    }
    {
        name: "core-binary-bytes-collect-rejects-dynamic-separator"
        category: "language-core"
        tags: [binary bytes collect diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes collect $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes collect requires a compile-time known binary separator in eBPF"
    }
    {
        name: "core-binary-bytes-collect-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes collect diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 1] | bytes collect'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes collect requires binary list items in eBPF; item 1 has type int"
    }
]
