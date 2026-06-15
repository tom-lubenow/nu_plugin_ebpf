const VERIFIER_DIFF_FIXTURES_1844_1875_A = [
    {
        name: "core-scalar-bits-rotate-unsigned-i64-runtime-reject"
        category: "language-core"
        tags: [scalar bits ror number-bytes runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits ror 1 --number-bytes 8'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror unsigned --number-bytes 8 runtime u32 input supports rotate counts 0, or from 33 through 64, in eBPF; got 1"
    }
    {
        name: "core-null-length"
        category: "language-core"
        tags: ["null" length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  null | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-length"
        category: "language-core"
        tags: [binary length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-length"
        category: "language-core"
        tags: [binary bytes length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-length-join"
        category: "language-core"
        tags: [binary list bytes length join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03] 0x[]] | bytes length | str join "-" | str starts-with "2-1-0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
