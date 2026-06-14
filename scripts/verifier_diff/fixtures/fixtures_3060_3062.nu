const VERIFIER_DIFF_FIXTURES_3060_3062 = [
    {
        name: "core-is-empty-runtime-scalar-input"
        category: "language-core"
        tags: [aggregate scalar is-empty input runtime accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-is-not-empty-runtime-scalar-input"
        category: "language-core"
        tags: [aggregate scalar is-not-empty input runtime accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
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
