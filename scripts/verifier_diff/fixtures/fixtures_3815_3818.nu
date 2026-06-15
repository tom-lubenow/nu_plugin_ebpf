const VERIFIER_DIFF_FIXTURES_3815_3818 = [
    {
        name: "core-bits-shl-list-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits shl signed list accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | bits shl --signed --number-bytes 8 (random int 0..63) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-shr-list-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits shr signed list accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | bits shr --signed --number-bytes 8 (random int 0..63) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-rol-list-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits rol signed list accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | bits rol --signed --number-bytes 8 (random int 0..64) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-ror-list-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits ror signed list accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | bits ror --signed --number-bytes 8 (random int 0..64) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
