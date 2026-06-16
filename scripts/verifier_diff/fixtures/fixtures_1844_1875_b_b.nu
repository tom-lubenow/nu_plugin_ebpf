const VERIFIER_DIFF_FIXTURES_1844_1875_B_B = [
    {
        name: "core-binary-list-bytes-reverse-unequal-get"
        category: "language-core"
        tags: [binary list bytes reverse unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | get 1 | bytes starts-with 0x[03 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-get-length"
        category: "language-core"
        tags: [binary list bytes reverse empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-last"
        category: "language-core"
        tags: [binary list bytes reverse unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | last | bytes starts-with 0x[03 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-describe"
        category: "language-core"
        tags: [binary list bytes reverse unequal describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | describe | str starts-with "list<binary>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-first-length"
        category: "language-core"
        tags: [binary list bytes reverse empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
