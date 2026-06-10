const VERIFIER_DIFF_FIXTURES_3066_3069 = [
    {
        name: "core-first-rejects-missing-pipeline-input"
        category: "language-core"
        tags: [aggregate list first diagnostics reject input missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  first'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first requires a pipeline input in eBPF"
    }
    {
        name: "core-last-rejects-missing-pipeline-input"
        category: "language-core"
        tags: [aggregate list last diagnostics reject input missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  last'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last requires a pipeline input in eBPF"
    }
    {
        name: "core-first-rejects-empty-stack-backed-list"
        category: "language-core"
        tags: [aggregate list first diagnostics reject empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | first'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first requires a stack-backed numeric list with proven non-empty length"
    }
    {
        name: "core-last-rejects-empty-stack-backed-list"
        category: "language-core"
        tags: [aggregate list last diagnostics reject empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | last'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last requires a stack-backed numeric list with proven non-empty length"
    }
]
