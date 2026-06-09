const VERIFIER_DIFF_FIXTURES_3095_3095 = [
    {
        name: "core-list-rejects-runtime-nonnumeric-item"
        category: "language-core"
        tags: [list diagnostics reject item type]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | math abs | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "eBPF runtime list literals currently support numeric scalar items only"
    }
]
