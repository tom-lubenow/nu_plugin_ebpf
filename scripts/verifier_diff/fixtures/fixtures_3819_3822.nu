const VERIFIER_DIFF_FIXTURES_3819_3822 = [
    {
        name: "core-bits-shl-runtime-list-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits shl signed list seq accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 3 | bits shl --signed --number-bytes 8 (random int 0..63) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-shr-runtime-list-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits shr signed list seq accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 3 | bits shr --signed --number-bytes 8 (random int 0..63) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-rol-runtime-list-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits rol signed list seq accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 3 | bits rol --signed --number-bytes 8 (random int 0..64) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-ror-runtime-list-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits ror signed list seq accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 3 | bits ror --signed --number-bytes 8 (random int 0..64) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
