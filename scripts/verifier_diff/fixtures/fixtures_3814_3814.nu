const VERIFIER_DIFF_FIXTURES_3814_3814 = [
    {
        name: "core-bits-and-accepts-dynamic-list-target"
        category: "language-core"
        tags: [bits and accept target dynamic list runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | bits and $ctx.pid | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
