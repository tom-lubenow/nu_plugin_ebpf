const VERIFIER_DIFF_FIXTURES_3826_3826 = [
    {
        name: "core-bytes-add-end-accepts-bounded-runtime-index"
        category: "language-core"
        tags: [binary bytes add end accept runtime runtime-index]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[01 03] | bytes add 0x[02] --end --index (random int 0..1) | bytes length) == 3'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
