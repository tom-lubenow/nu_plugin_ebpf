const VERIFIER_DIFF_FIXTURES_2715_2724 = [
    {
        name: "core-list-compact-rejects-fixed-list-column-argument"
        category: "language-core"
        tags: [list compact diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" ""] | compact value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "compact does not accept column arguments for non-record fixed lists in eBPF"
    }
    {
        name: "core-list-compact-rejects-missing-pipeline"
        category: "language-core"
        tags: [list compact diagnostics reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  compact'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "compact requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-list-uniq-rejects-missing-pipeline"
        category: "language-core"
        tags: [list uniq diagnostics reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  uniq'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "uniq requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-list-uniq-rejects-scalar-input"
        category: "language-core"
        tags: [list uniq diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | uniq'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "uniq requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-find-rejects-missing-pipeline"
        category: "language-core"
        tags: [list find diagnostics reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  find 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "find requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-list-find-rejects-scalar-input"
        category: "language-core"
        tags: [list find diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | find 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "find requires a stack-backed numeric list input in eBPF"
    }
    {
        name: "core-list-sort-rejects-missing-pipeline"
        category: "language-core"
        tags: [list sort diagnostics reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  sort'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort requires a pipeline input with tracked metadata in eBPF"
    }
    {
        name: "core-list-sort-rejects-scalar-input"
        category: "language-core"
        tags: [list sort diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | sort'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-sort-rejects-stack-capacity"
        category: "language-core"
        tags: [list sort diagnostics reject capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 20 | sort'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort supports stack-backed numeric lists with capacity <= 16 in eBPF"
    }
    {
        name: "core-list-split-list-rejects-heterogeneous-groups"
        category: "language-core"
        tags: [list split-list diagnostics reject layout]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x" "a"] | split list "x"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list result requires homogeneous fixed-layout groups in eBPF"
    }
]
