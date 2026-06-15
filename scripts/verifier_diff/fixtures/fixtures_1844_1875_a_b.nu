const VERIFIER_DIFF_FIXTURES_1844_1875_A_B = [
    {
        name: "core-binary-bytes-starts-with"
        category: "language-core"
        tags: [binary bytes starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-ends-with"
        category: "language-core"
        tags: [binary bytes ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes ends-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-starts-with"
        category: "language-core"
        tags: [binary list bytes starts-with get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes starts-with 0x[03] | get 1) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-ends-with"
        category: "language-core"
        tags: [binary list bytes ends-with get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes ends-with 0x[02] | get 0) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
