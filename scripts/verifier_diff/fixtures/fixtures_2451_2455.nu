const VERIFIER_DIFF_FIXTURES_2451_2455 = [
    {
        name: "core-binary-bytes-at-rejects-dynamic-input"
        category: "language-core"
        tags: [binary bytes at diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes at 0..1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes at requires compile-time known binary or list<binary> input in eBPF"
    }
    {
        name: "core-binary-bytes-at-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes at diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 1] | bytes at 0..0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes at requires binary list items in eBPF; item 1 has type int"
    }
    {
        name: "core-binary-bytes-at-rejects-empty-list-result"
        category: "language-core"
        tags: [binary bytes at diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes at 0..0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes at requires a non-empty list<binary> result in eBPF"
    }
    {
        name: "core-binary-bytes-at-rejects-empty-list-items"
        category: "language-core"
        tags: [binary bytes at diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes at 1..0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes at requires non-empty binary list results in eBPF"
    }
    {
        name: "core-binary-bytes-at-rejects-unequal-list-items"
        category: "language-core"
        tags: [binary bytes at diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes at 0..2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes at requires equal-length binary list results in eBPF"
    }
]
