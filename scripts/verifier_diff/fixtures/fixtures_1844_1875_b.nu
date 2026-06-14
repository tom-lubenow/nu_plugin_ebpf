const VERIFIER_DIFF_FIXTURES_1844_1875_B = [
    {
        name: "core-binary-bytes-reverse-empty-length"
        category: "language-core"
        tags: [binary bytes reverse empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes reverse | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse"
        category: "language-core"
        tags: [binary list bytes reverse get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes reverse | get 0 | bytes starts-with 0x[02]) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes reverse empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes reverse unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-list-length"
        category: "language-core"
        tags: [binary list bytes reverse empty_list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes reverse | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-list-is-empty"
        category: "language-core"
        tags: [binary list bytes reverse empty_list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes reverse | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "core-binary-bytes-build-starts-with"
        category: "language-core"
        tags: [binary bytes build starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build 0x[01 02] 0x[03] 4 | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-build-empty-length"
        category: "language-core"
        tags: [binary bytes build empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-starts-with"
        category: "language-core"
        tags: [binary bytes at starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04] | bytes at 1..2 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-explicit-step-starts-with"
        category: "language-core"
        tags: [binary bytes at range step starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04 05 06] | bytes at 1..3..4 | bytes starts-with 0x[02 03 04 05]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-empty-length"
        category: "language-core"
        tags: [binary bytes at empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02] | bytes at 1..0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-collect"
        category: "language-core"
        tags: [binary list bytes at collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | bytes at 0..0 | bytes collect | bytes starts-with 0x[01 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
