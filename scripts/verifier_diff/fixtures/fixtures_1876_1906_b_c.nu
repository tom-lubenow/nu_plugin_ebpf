const VERIFIER_DIFF_FIXTURES_1876_1906_B_C = [
    {
        name: "core-binary-bytes-remove-starts-with"
        category: "language-core"
        tags: [binary bytes remove starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa 10 bb 10] | bytes remove --all 0x[10] | bytes starts-with 0x[aa bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-remove-empty-length"
        category: "language-core"
        tags: [binary bytes remove empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10] | bytes remove 0x[10] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
