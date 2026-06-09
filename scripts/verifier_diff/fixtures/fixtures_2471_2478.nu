const VERIFIER_DIFF_FIXTURES_2471_2478 = [
    {
        name: "core-binary-bytes-replace-rejects-dynamic-input"
        category: "language-core"
        tags: [binary bytes replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes replace 0x[10] 0x[a0]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes replace requires compile-time known binary or list<binary> input in eBPF"
    }
    {
        name: "core-binary-bytes-replace-rejects-dynamic-pattern"
        category: "language-core"
        tags: [binary bytes replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa] | bytes replace $ctx.comm 0x[a0]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes replace requires a compile-time known binary pattern in eBPF"
    }
    {
        name: "core-binary-bytes-replace-rejects-empty-pattern"
        category: "language-core"
        tags: [binary bytes replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa] | bytes replace 0x[] 0x[a0]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes replace requires a non-empty binary pattern in eBPF"
    }
    {
        name: "core-binary-bytes-replace-rejects-dynamic-replacement"
        category: "language-core"
        tags: [binary bytes replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa] | bytes replace 0x[10] $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes replace requires compile-time known binary replacement in eBPF"
    }
    {
        name: "core-binary-bytes-replace-rejects-empty-list-result"
        category: "language-core"
        tags: [binary bytes replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes replace 0x[10] 0x[a0]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes replace requires a non-empty list<binary> result in eBPF"
    }
    {
        name: "core-binary-bytes-replace-rejects-list-item-type"
        category: "language-core"
        tags: [binary bytes replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 1] | bytes replace 0x[10] 0x[]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes replace requires binary list items in eBPF; item 1 has type int"
    }
    {
        name: "core-binary-bytes-replace-rejects-empty-list-items"
        category: "language-core"
        tags: [binary bytes replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes replace requires non-empty binary list results in eBPF"
    }
    {
        name: "core-binary-bytes-replace-rejects-unequal-list-items"
        category: "language-core"
        tags: [binary bytes replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes replace requires equal-length binary list results in eBPF"
    }
]
