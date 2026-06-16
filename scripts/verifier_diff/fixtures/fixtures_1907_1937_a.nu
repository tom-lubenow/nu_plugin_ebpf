const VERIFIER_DIFF_FIXTURES_1907_1937_A = [
    {
        name: "core-binary-bytes-replace-starts-with"
        category: "language-core"
        tags: [binary bytes replace starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa 10 bb 10] | bytes replace --all 0x[10] 0x[a0] | bytes starts-with 0x[a0 aa a0]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-replace-empty-length"
        category: "language-core"
        tags: [binary bytes replace empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10] | bytes replace 0x[10] 0x[] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-starts-with"
        category: "language-core"
        tags: [binary bytes collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[11] 0x[33] 0x[44]] | bytes collect 0x[01] | bytes starts-with 0x[11 01 33]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-empty-length"
        category: "language-core"
        tags: [binary bytes collect empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[]] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-empty-list-predicates"
        category: "language-core"
        tags: [binary bytes collect empty list predicates]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([] | bytes collect | is-empty) and (not ([] | bytes collect | is-not-empty))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-empty-separator-length"
        category: "language-core"
        tags: [binary bytes collect empty separator length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes collect 0x[] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
