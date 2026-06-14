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
    {
        name: "core-binary-bytes-index-of"
        category: "language-core"
        tags: [binary bytes index-of]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-end"
        category: "language-core"
        tags: [binary bytes index-of end]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --end 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-index-of"
        category: "language-core"
        tags: [binary list bytes index-of get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 02 02]] | bytes index-of 0x[02] | get 1) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-index-of-end"
        category: "language-core"
        tags: [binary list bytes index-of end get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[02 01 02] 0x[03 04]] | bytes index-of --end 0x[02] | get 0) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
