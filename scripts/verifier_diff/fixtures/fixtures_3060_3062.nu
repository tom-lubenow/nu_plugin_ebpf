const VERIFIER_DIFF_FIXTURES_3060_3062 = [
    {
        name: "core-is-empty-rejects-runtime-scalar-input"
        category: "language-core"
        tags: [aggregate is-empty diagnostics reject input runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | is-empty'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "is-empty requires a stack-backed list, tracked string, typed fixed array, metadata-backed or typed global record, or literal null input in eBPF"
    }
    {
        name: "core-is-not-empty-rejects-runtime-scalar-input"
        category: "language-core"
        tags: [aggregate is-not-empty diagnostics reject input runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | is-not-empty'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "is-not-empty requires a stack-backed list, tracked string, typed fixed array, metadata-backed or typed global record, or literal null input in eBPF"
    }
    {
        name: "core-length-rejects-runtime-scalar-input"
        category: "language-core"
        tags: [aggregate length diagnostics reject input runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "length requires a stack-backed list, typed fixed array, metadata-backed or typed global record, literal binary, or literal null input in eBPF"
    }
]
