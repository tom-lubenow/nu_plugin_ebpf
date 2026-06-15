const VERIFIER_DIFF_FIXTURES_1844_1875_A_D = [
    {
        name: "core-binary-bytes-index-of-all-join"
        category: "language-core"
        tags: [binary bytes index-of all join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --all 0x[02] | str join "-" | str starts-with "1-3"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-index-of-all-get-join"
        category: "language-core"
        tags: [binary list bytes index-of all get join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 02]] | bytes index-of --all 0x[02] | get 0 | str join "-" | str starts-with "1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-all-missing-length"
        category: "language-core"
        tags: [binary bytes index-of all missing length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[01 02] | bytes index-of --all 0x[03] | length) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-all-end-join"
        category: "language-core"
        tags: [binary bytes index-of all end join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --all --end 0x[02] | str join "-" | str starts-with "3-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-reverse-starts-with"
        category: "language-core"
        tags: [binary bytes reverse starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes reverse | bytes starts-with 0x[03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
