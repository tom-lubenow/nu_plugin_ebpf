const VERIFIER_DIFF_FIXTURES_2448_2450 = [
    {
        name: "core-binary-bytes-build-rejects-dynamic-argument"
        category: "language-core"
        tags: [binary bytes build diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes build requires compile-time known arguments in eBPF"
    }
    {
        name: "core-binary-bytes-build-rejects-out-of-range-integer"
        category: "language-core"
        tags: [binary bytes build diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build 256'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes build integer arguments must be in 0..=255 in eBPF"
    }
    {
        name: "core-binary-bytes-build-rejects-unsupported-argument-type"
        category: "language-core"
        tags: [binary bytes build diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build "x"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes build supports only binary and integer byte arguments in eBPF"
    }
]
