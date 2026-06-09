const VERIFIER_DIFF_FIXTURES_2957_2966 = [
    {
        name: "core-bytes-length-rejects-cell-path-argument"
        category: "language-core"
        tags: [binary bytes length diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61] | bytes length foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes length does not accept arguments in eBPF"
    }
    {
        name: "core-bytes-at-rejects-extra-cell-path-argument"
        category: "language-core"
        tags: [binary bytes at diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[6162] | bytes at 0..1 foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes at accepts exactly one range argument in eBPF"
    }
    {
        name: "core-bytes-at-rejects-dynamic-range"
        category: "language-core"
        tags: [binary bytes at diagnostics reject range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[6162] | bytes at $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes at requires a compile-time known range in eBPF"
    }
    {
        name: "core-bytes-length-rejects-dynamic-string-input"
        category: "language-core"
        tags: [binary bytes length diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes length requires compile-time known binary or list<binary> input in eBPF"
    }
    {
        name: "core-bytes-starts-with-rejects-dynamic-string-input"
        category: "language-core"
        tags: [binary bytes starts-with diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes starts-with 0x[61]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes starts-with requires compile-time known binary or list<binary> input in eBPF"
    }
    {
        name: "core-bytes-starts-with-rejects-dynamic-pattern"
        category: "language-core"
        tags: [binary bytes starts-with diagnostics reject pattern dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[6162] | bytes starts-with $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes starts-with requires a compile-time known binary pattern in eBPF"
    }
    {
        name: "core-bytes-ends-with-rejects-dynamic-string-input"
        category: "language-core"
        tags: [binary bytes ends-with diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bytes ends-with 0x[61]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes ends-with requires compile-time known binary or list<binary> input in eBPF"
    }
    {
        name: "core-bytes-ends-with-rejects-dynamic-pattern"
        category: "language-core"
        tags: [binary bytes ends-with diagnostics reject pattern dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[6162] | bytes ends-with $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes ends-with requires a compile-time known binary pattern in eBPF"
    }
    {
        name: "core-bytes-add-rejects-extra-cell-path-argument"
        category: "language-core"
        tags: [binary bytes add diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[6162] | bytes add 0x[63] foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes add accepts exactly one binary data argument in eBPF"
    }
    {
        name: "core-bits-not-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits not diagnostics reject flags]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits not --signed --signed'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not supports only --signed or --number-bytes for integer input in eBPF"
    }
]
