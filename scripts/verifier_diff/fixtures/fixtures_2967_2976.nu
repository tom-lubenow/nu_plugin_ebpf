const VERIFIER_DIFF_FIXTURES_2967_2976 = [
    {
        name: "core-binary-bytes-length-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes length diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[61] 1] | bytes length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes length requires binary list items in eBPF; item 1 has type int"
    }
    {
        name: "core-binary-bytes-starts-with-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes starts-with diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[61] 1] | bytes starts-with 0x[61]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes starts-with requires binary list items in eBPF; item 1 has type int"
    }
    {
        name: "core-binary-bytes-ends-with-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes ends-with diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[61] 1] | bytes ends-with 0x[61]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes ends-with requires binary list items in eBPF; item 1 has type int"
    }
    {
        name: "core-binary-bytes-reverse-rejects-empty-list-result"
        category: "language-core"
        tags: [binary bytes reverse diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes reverse requires a non-empty list<binary> result in eBPF"
    }
    {
        name: "core-binary-bytes-reverse-rejects-empty-list-items"
        category: "language-core"
        tags: [binary bytes reverse diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes reverse requires non-empty binary list results in eBPF"
    }
    {
        name: "core-binary-bytes-reverse-rejects-unequal-list-items"
        category: "language-core"
        tags: [binary bytes reverse diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes reverse requires equal-length binary list results in eBPF"
    }
    {
        name: "core-binary-bytes-index-of-all-rejects-result-capacity"
        category: "language-core"
        tags: [binary bytes index-of diagnostics reject capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01] | bytes index-of --all 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes index-of --all result exceeds eBPF numeric list capacity 60"
    }
    {
        name: "core-binary-bytes-index-of-all-rejects-list-item-result-capacity"
        category: "language-core"
        tags: [binary bytes index-of diagnostics reject capacity list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01]] | bytes index-of --all 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes index-of --all result for binary-list item 0 exceeds eBPF numeric list capacity 60"
    }
    {
        name: "core-binary-bytes-at-rejects-record-input"
        category: "language-core"
        tags: [binary bytes at diagnostics reject input record]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {a: 0x[61]} | bytes at 0..1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes at requires binary or list<binary> input in eBPF, got record<a: binary>"
    }
    {
        name: "core-binary-bytes-add-rejects-record-input"
        category: "language-core"
        tags: [binary bytes add diagnostics reject input record]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {a: 0x[61]} | bytes add 0x[62]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add requires binary or list<binary> input in eBPF, got record<a: binary>"
    }
]
