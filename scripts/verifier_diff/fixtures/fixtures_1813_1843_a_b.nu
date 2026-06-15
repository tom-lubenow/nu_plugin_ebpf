const VERIFIER_DIFF_FIXTURES_1813_1843_A_B = [
    {
        name: "core-list-binary-bits-unary-shift-describe"
        category: "language-core"
        tags: [aggregate list binary bits "not" shl ror describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((([0x[ff] 0x[00 01]] | bits not --signed --number-bytes 8 | describe | str starts-with "list<binary>") and ([0x[80] 0x[01 02]] | bits shl 1 | describe | str starts-with "list<binary>")) and ([0x[80] 0x[01 02]] | bits ror 1 | describe | str starts-with "list<binary>"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-binary-bits-unary-shift-metadata"
        category: "language-core"
        tags: [aggregate list binary bits "not" shl ror length predicates metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((([0x[] 0x[]] | bits not --signed --number-bytes 8 | length) == 2) and ([0x[] 0x[]] | bits not --signed --number-bytes 8 | is-not-empty)) and (([0x[80] 0x[01 02]] | bits shl 1 | length) == 2)) and ([0x[80] 0x[01 02]] | bits ror 1 | is-not-empty)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-number-bytes"
        category: "language-core"
        tags: [aggregate list bits shl number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([127 128 -129] | bits shl 1 --number-bytes 1 | math sum) == 252'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-number-bytes-runtime"
        category: "language-core"
        tags: [aggregate list bits shl number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shl 1 --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-fixed-runtime"
        category: "language-core"
        tags: [aggregate list bits shl signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shl 1 --signed --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-unsigned-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits shr number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shr 1 --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-default-runtime"
        category: "language-core"
        tags: [aggregate list bits shl shr default runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((([(random int)] | bits shl 0 | length) == 1) and (([(random int)] | bits shr 0 | length) == 1)) and (([(random int)] | bits shr 1 | length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-signed-i64-runtime"
        category: "language-core"
        tags: [scalar bits shr signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits shr 1 --signed --number-bytes 8) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits shl number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits shl 1 --number-bytes 1) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
