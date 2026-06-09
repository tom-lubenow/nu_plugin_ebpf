const VERIFIER_DIFF_FIXTURES_2456_2463 = [
    {
        name: "core-binary-bytes-add-rejects-dynamic-input"
        category: "language-core"
        tags: [binary bytes add diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes add 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add requires compile-time known binary or list<binary> input in eBPF"
    }
    {
        name: "core-binary-bytes-add-rejects-dynamic-data"
        category: "language-core"
        tags: [binary bytes add diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bytes add $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add requires compile-time known binary data in eBPF"
    }
    {
        name: "core-binary-bytes-add-rejects-dynamic-index"
        category: "language-core"
        tags: [binary bytes add diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bytes add 0x[02] --index $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add --index requires a compile-time known integer in eBPF"
    }
    {
        name: "core-binary-bytes-add-rejects-negative-index"
        category: "language-core"
        tags: [binary bytes add diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bytes add 0x[02] --index -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add --index requires a non-negative integer in eBPF"
    }
    {
        name: "core-binary-bytes-add-rejects-empty-list-result"
        category: "language-core"
        tags: [binary bytes add diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes add 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add requires a non-empty list<binary> result in eBPF"
    }
    {
        name: "core-binary-bytes-add-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes add diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 1] | bytes add 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add requires binary list items in eBPF; item 1 has type int"
    }
    {
        name: "core-binary-bytes-add-rejects-empty-list-items"
        category: "language-core"
        tags: [binary bytes add diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes add 0x[]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add requires non-empty binary list results in eBPF"
    }
    {
        name: "core-binary-bytes-add-rejects-unequal-list-items"
        category: "language-core"
        tags: [binary bytes add diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes add 0x[]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add requires equal-length binary list results in eBPF"
    }
]
