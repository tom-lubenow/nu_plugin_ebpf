const VERIFIER_DIFF_FIXTURES_3827_3827 = [
    {
        name: "core-get-binary-list-accepts-range-proven-runtime-index"
        category: "language-core"
        tags: [aggregate list get binary accept runtime runtime-index]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | get (random int 0..1) | bytes length) == 2'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
