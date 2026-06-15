const VERIFIER_DIFF_FIXTURES_3805_3808 = [
    {
        name: "core-bits-shl-signed-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits shl signed accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shl --signed --number-bytes 8 (random int 0..63)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-shr-signed-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits shr signed accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shr --signed --number-bytes 8 (random int 0..63)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-rol-signed-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits rol signed accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits rol --signed --number-bytes 8 (random int 0..64)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-bits-ror-signed-accepts-bounded-runtime-count"
        category: "language-core"
        tags: [bits ror signed accept runtime runtime-count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits ror --signed --number-bytes 8 (random int 0..64)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
