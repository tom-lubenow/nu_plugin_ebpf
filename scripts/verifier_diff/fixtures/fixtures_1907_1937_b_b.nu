const VERIFIER_DIFF_FIXTURES_1907_1937_B_B = [
    {
        name: "core-binary-bytes-split-collect-starts-with"
        category: "language-core"
        tags: [binary bytes split collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 2d 2d 62 2d 2d 63] | bytes split "--" | bytes collect 0x[20] | bytes starts-with 0x[61 20 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-part-collect-length"
        category: "language-core"
        tags: [binary bytes split empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-collect-length"
        category: "language-core"
        tags: [binary bytes split unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-describe"
        category: "language-core"
        tags: [binary bytes split unequal describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | describe | str starts-with "list<binary>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-get"
        category: "language-core"
        tags: [binary bytes split unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | get 1 | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
