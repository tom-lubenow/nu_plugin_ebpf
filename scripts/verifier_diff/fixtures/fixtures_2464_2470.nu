const VERIFIER_DIFF_FIXTURES_2464_2470 = [
    {
        name: "core-binary-bytes-remove-rejects-dynamic-input"
        category: "language-core"
        tags: [binary bytes remove diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes remove 0x[10]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes remove requires compile-time known binary or list<binary> input in eBPF"
    }
    {
        name: "core-binary-bytes-remove-rejects-dynamic-pattern"
        category: "language-core"
        tags: [binary bytes remove diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa] | bytes remove $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes remove requires a compile-time known binary pattern in eBPF"
    }
    {
        name: "core-binary-bytes-remove-rejects-empty-pattern"
        category: "language-core"
        tags: [binary bytes remove diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa] | bytes remove 0x[]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes remove requires a non-empty binary pattern in eBPF"
    }
    {
        name: "core-binary-bytes-remove-rejects-empty-list-result"
        category: "language-core"
        tags: [binary bytes remove diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes remove 0x[10]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes remove requires a non-empty list<binary> result in eBPF"
    }
    {
        name: "core-binary-bytes-remove-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes remove diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 1] | bytes remove 0x[10]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes remove requires binary list items in eBPF; item 1 has type int"
    }
    {
        name: "core-binary-bytes-remove-rejects-empty-list-items"
        category: "language-core"
        tags: [binary bytes remove diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes remove requires non-empty binary list results in eBPF"
    }
    {
        name: "core-binary-bytes-remove-rejects-unequal-list-items"
        category: "language-core"
        tags: [binary bytes remove diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes remove 0x[ff]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes remove requires equal-length binary list results in eBPF"
    }
]
