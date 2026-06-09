const VERIFIER_DIFF_FIXTURES_2446_2447 = [
    {
        name: "core-binary-bytes-reverse-rejects-dynamic-input"
        category: "language-core"
        tags: [binary bytes reverse diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes reverse requires compile-time known binary or list<binary> input in eBPF"
    }
    {
        name: "core-binary-bytes-reverse-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes reverse diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 1] | bytes reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes reverse requires binary list items in eBPF; item 1 has type int"
    }
]
