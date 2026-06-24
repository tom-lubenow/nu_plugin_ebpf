const VERIFIER_DIFF_FIXTURES_2715_2724 = [
    {
        name: "core-list-compact-fixed-list-column-argument"
        category: "language-core"
        tags: [list compact column accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" ""] | compact value | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
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
        name: "global-define-type-array-u32-sort-large-initializer-first"
        category: "globals"
        tags: [globals arrays u32 sort first initializer capacity accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16] | global-define --type "array{u32:17}" ports'
            '  (((global-get ports) | sort | first) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
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
