const VERIFIER_DIFF_FIXTURES_1813_1843_A = [
    {
        name: "core-list-bits-not-binary-first-last-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" first last bytes length starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[ff] 0x[00 01]] | bits not | first | bytes length) == 1) and (([0x[ff] 0x[00 01]] | bits not | last | bytes starts-with 0x[ff fe]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-binary-bits-not-access-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" get first bytes length starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[ff] 0x[00 01]] | bits not --signed --number-bytes 8 | get 1 | bytes starts-with 0x[ff fe]) == 1) and (([0x[] 0x[01]] | bits not --signed --number-bytes 8 | first | bytes length) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-binary-empty-predicate-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[]] | bits not | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-default"
        category: "language-core"
        tags: [aggregate list bits "not"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 256 -129] | bits not | math sum) == 65658'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-signed-i64"
        category: "language-core"
        tags: [scalar bits shl shr signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits shl 1 --signed --number-bytes 8) == 8) and ((-8 | bits shr 1 --signed --number-bytes 8) == -4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-i64"
        category: "language-core"
        tags: [aggregate list bits shl signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits shl 1 --signed --number-bytes 8 | math sum) == 18'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits shr signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shr 1 --signed --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-number-bytes"
        category: "language-core"
        tags: [scalar bits shl shr signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((255 | bits shl 1 --number-bytes 1) == 254) and ((-65 | bits shr 1 --number-bytes 1) == -33) and ((127 | bits shl 1 --signed --number-bytes 1) == -2) and ((128 | bits shr 1 --signed --number-bytes 1) == -64) and ((4294967296 | bits shl 1 --number-bytes 8) == 8589934592)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-rotate-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits shl shr rol ror signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[4f f4] | bits shl 4 | bytes starts-with 0x[ff 40]) and (0x[4f f4] | bits shr 4 --signed --number-bytes 8 | bytes starts-with 0x[04 ff]) and (0x[c0 ff ee] | bits rol 10 --signed --number-bytes 8 | bytes starts-with 0x[ff bb 03]) and (0x[ff bb 03] | bits ror 10 --number-bytes 8 | bytes starts-with 0x[c0 ff ee])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-rotate-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits shl ror bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[80] 0x[01 02]] | bits shl 1 | bytes collect | bytes length) == 3) and (([0x[80] 0x[01 02]] | bits ror 1 | bytes collect | bytes length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-binary-bits-shift-rotate-access-fold"
        category: "language-core"
        tags: [aggregate list binary bits shl ror last bytes length starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[80] 0x[01 00]] | bits shl 1 | last | bytes starts-with 0x[02 00]) == 1) and (([0x[80] 0x[01 02]] | bits ror 1 | last | bytes length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
