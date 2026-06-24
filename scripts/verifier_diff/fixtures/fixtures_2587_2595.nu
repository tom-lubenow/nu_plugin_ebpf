const VERIFIER_DIFF_FIXTURES_2587_2595 = [
    {
        name: "core-list-find-regex"
        category: "language-core"
        tags: [list find regex accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | find --regex 2 | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find-invert"
        category: "language-core"
        tags: [list find invert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 2] | find --invert 2 | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find-multiple-search-terms"
        category: "language-core"
        tags: [list find multi accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 2] | find 2 3 | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
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
        error_contains: "find requires at least one numeric search argument in eBPF"
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
        name: "core-list-find-dynamic-string-fixed-list-length"
        category: "language-core"
        tags: [list find string length accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b"] | find $ctx.comm | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find-float-seq-length"
        category: "language-core"
        tags: [list seq find float length accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 3) | find 2.5 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
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
            '  $ctx.pid | compact'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "compact requires a stack-backed numeric list input in eBPF"
    }
    {
        name: "core-list-compact-seq-column-argument"
        category: "language-core"
        tags: [list compact column accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 3) | compact value | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
