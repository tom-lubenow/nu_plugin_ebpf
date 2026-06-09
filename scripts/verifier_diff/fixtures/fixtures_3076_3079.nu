const VERIFIER_DIFF_FIXTURES_3076_3079 = [
    {
        name: "core-list-reverse-rejects-missing-pipeline-input"
        category: "list-diagnostics"
        tags: [aggregate list reverse diagnostics reject input missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reverse requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-list-take-rejects-missing-pipeline-input"
        category: "list-diagnostics"
        tags: [aggregate list take diagnostics reject input missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  take 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "take requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-list-skip-rejects-missing-pipeline-input"
        category: "list-diagnostics"
        tags: [aggregate list skip diagnostics reject input missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  skip 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skip requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-list-drop-rejects-missing-pipeline-input"
        category: "list-diagnostics"
        tags: [aggregate list drop diagnostics reject input missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  drop 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "drop requires a pipeline input with tracked metadata in eBPF"
    }
]
