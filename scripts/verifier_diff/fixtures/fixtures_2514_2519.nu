const VERIFIER_DIFF_FIXTURES_2514_2519 = [
    {
        name: "core-string-split-row-rejects-dynamic-input"
        category: "language-core"
        tags: [string split row diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | split row ","'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split row requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-split-row-rejects-dynamic-separator"
        category: "language-core"
        tags: [string split row diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a,b" | split row $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split row separator requires a compile-time string literal"
    }
    {
        name: "core-string-split-row-rejects-list-item-type"
        category: "language-core"
        tags: [string split row diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a,b" 1] | split row ","'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split row requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-split-row-rejects-dynamic-number"
        category: "language-core"
        tags: [string split row diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a,b" | split row "," --number $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split row --number requires a compile-time known integer in eBPF"
    }
    {
        name: "core-string-split-row-rejects-negative-number"
        category: "language-core"
        tags: [string split row diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a,b" | split row "," --number -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split row --number requires a non-negative integer in eBPF"
    }
    {
        name: "core-string-split-row-rejects-invalid-regex"
        category: "language-core"
        tags: [string split row regex diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a1b" | split row --regex "["'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split row --regex pattern is invalid in eBPF"
    }
]
