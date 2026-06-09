const VERIFIER_DIFF_FIXTURES_2482_2486 = [
    {
        name: "core-binary-bytes-split-rejects-dynamic-input"
        category: "language-core"
        tags: [binary bytes split diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes split 0x[20]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes split requires compile-time known binary input in eBPF"
    }
    {
        name: "core-binary-bytes-split-rejects-dynamic-separator"
        category: "language-core"
        tags: [binary bytes split diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02] | bytes split $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes split requires a compile-time known binary or string separator in eBPF"
    }
    {
        name: "core-binary-bytes-split-rejects-empty-separator"
        category: "language-core"
        tags: [binary bytes split diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02] | bytes split 0x[]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes split requires a non-empty separator in eBPF"
    }
    {
        name: "core-binary-bytes-split-rejects-empty-materialized-parts"
        category: "language-core"
        tags: [binary bytes split diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes split requires non-empty binary parts in eBPF"
    }
    {
        name: "core-binary-bytes-split-rejects-unequal-materialized-parts"
        category: "language-core"
        tags: [binary bytes split diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes split requires equal-length binary parts in eBPF"
    }
]
