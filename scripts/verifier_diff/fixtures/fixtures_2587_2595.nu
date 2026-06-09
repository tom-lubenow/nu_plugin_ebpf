const VERIFIER_DIFF_FIXTURES_2587_2595 = [
    {
        name: "core-list-find-rejects-flags"
        category: "language-core"
        tags: [list find diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | find --regex 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "find does not accept flags or named arguments for stack-backed numeric lists in eBPF"
    }
    {
        name: "core-list-find-rejects-missing-search-argument"
        category: "language-core"
        tags: [list find diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | find'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "find requires exactly one numeric search argument in eBPF"
    }
    {
        name: "core-list-find-rejects-dynamic-fixed-list-search"
        category: "language-core"
        tags: [list find string diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b"] | find $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "find search argument must be compile-time constant for compile-time known fixed lists in eBPF"
    }
    {
        name: "core-list-find-rejects-float-stack-search"
        category: "language-core"
        tags: [list find diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 3) | find 2.5'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "find search argument must be an integer scalar for stack-backed numeric lists in eBPF"
    }
    {
        name: "core-list-find-rejects-dynamic-string-stack-search"
        category: "language-core"
        tags: [list find string diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 3) | find $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "find search argument must be a numeric scalar in eBPF"
    }
    {
        name: "core-list-sort-rejects-mixed-fixed-list"
        category: "language-core"
        tags: [list sort diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "a"] | sort'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort requires compile-time known fixed-list elements with one comparable type in eBPF"
    }
    {
        name: "core-list-sort-rejects-record-fixed-list"
        category: "language-core"
        tags: [list sort record diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [{a: 1}] | sort'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort supports compile-time known fixed lists with boolean, integer, finite float, binary, or string elements in eBPF"
    }
    {
        name: "core-list-compact-rejects-dynamic-input"
        category: "language-core"
        tags: [list compact diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | compact'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "compact requires a stack-backed numeric list input in eBPF"
    }
    {
        name: "core-list-compact-rejects-stack-column-argument"
        category: "language-core"
        tags: [list compact diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 3) | compact value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "compact does not accept column arguments for stack-backed numeric lists in eBPF"
    }
]
