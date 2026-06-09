const VERIFIER_DIFF_FIXTURES_3063_3065 = [
    {
        name: "core-get-rejects-fixed-list-negative-index"
        category: "language-core"
        tags: [aggregate list get diagnostics reject index negative]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b"] | get (-1) | str length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index must be non-negative for compile-time known fixed lists in eBPF"
    }
    {
        name: "core-get-rejects-fixed-list-out-of-bounds"
        category: "language-core"
        tags: [aggregate list get diagnostics reject index bounds]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b"] | get 3 | str length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index 3 is out of bounds for compile-time known fixed list with length 2 in eBPF"
    }
    {
        name: "core-get-rejects-fixed-list-dynamic-index"
        category: "language-core"
        tags: [aggregate list get diagnostics reject index dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b"] | get $ctx.pid | str length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index must be compile-time constant for compile-time known fixed lists in eBPF"
    }
]
