const VERIFIER_DIFF_FIXTURES_1907_1937_B_C = [
    {
        name: "core-binary-bytes-split-empty-get-length"
        category: "language-core"
        tags: [binary bytes split empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-last"
        category: "language-core"
        tags: [binary bytes split unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | last | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-first-length"
        category: "language-core"
        tags: [binary bytes split empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
