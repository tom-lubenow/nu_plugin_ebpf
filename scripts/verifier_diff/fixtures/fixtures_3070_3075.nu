const VERIFIER_DIFF_FIXTURES_3070_3075 = [
    {
        name: "core-append-rejects-missing-pipeline-input"
        category: "language-core"
        tags: [aggregate list append diagnostics reject input missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  append 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "append requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-prepend-rejects-missing-pipeline-input"
        category: "language-core"
        tags: [aggregate list prepend diagnostics reject input missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  prepend 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "prepend requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-append-rejects-non-list-input"
        category: "language-core"
        tags: [aggregate list append diagnostics reject input scalar]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | append 2 | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "append requires a stack-backed list input in eBPF"
    }
    {
        name: "core-prepend-rejects-non-list-input"
        category: "language-core"
        tags: [aggregate list prepend diagnostics reject input scalar]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | prepend 2 | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "prepend requires a stack-backed list input in eBPF"
    }
    {
        name: "core-append-rejects-dynamic-item-for-fixed-list"
        category: "language-core"
        tags: [aggregate list append diagnostics reject item dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a"] | append $ctx.pid | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "append item must be compile-time constant for compile-time known fixed lists in eBPF"
    }
    {
        name: "core-prepend-rejects-dynamic-item-for-fixed-list"
        category: "language-core"
        tags: [aggregate list prepend diagnostics reject item dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a"] | prepend $ctx.pid | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "prepend item must be compile-time constant for compile-time known fixed lists in eBPF"
    }
]
