const VERIFIER_DIFF_FIXTURES_1813_1843 = [
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
    {
        name: "core-scalar-bits-shift-unsigned-i64-left-u32-runtime"
        category: "language-core"
        tags: [scalar bits shl number-bytes runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.pid | bits shl 1 --number-bytes 8) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-default"
        category: "language-core"
        tags: [scalar bits shl shr default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((128 | bits shl 1) == 0) and ((-129 | bits shr 1) == -65) and ((4294967296 | bits shl 1) == 8589934592)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-default-runtime-reject"
        category: "language-core"
        tags: [scalar bits shl default runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl default auto-width shifts require compile-time known integer input"
    }
    {
        name: "core-scalar-bits-shift-unsigned-i64-runtime"
        category: "language-core"
        tags: [scalar bits shr number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shr 1 --number-bytes 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-signed-i64"
        category: "language-core"
        tags: [scalar bits rol ror signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((1 | bits rol 1 --signed --number-bytes 8) == 2) and ((1 | bits ror 1 --signed --number-bytes 8) == -9223372036854775808) and ((1 | bits rol 64 --signed --number-bytes 8) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-i64"
        category: "language-core"
        tags: [aggregate list bits rol signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits rol 1 --signed --number-bytes 8 | math sum) == 18'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits ror signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --signed --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-number-bytes"
        category: "language-core"
        tags: [scalar bits rol ror signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((127 | bits rol 1 --number-bytes 1) == 254) and ((-65 | bits ror 1 --number-bytes 1) == -33) and ((1 | bits ror 32 --number-bytes 4) == 1) and ((1 | bits ror 1 --signed --number-bytes 1) == -128) and ((4294967296 | bits ror 1 --number-bytes 8) == 2147483648)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-number-bytes"
        category: "language-core"
        tags: [aggregate list bits rol number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([127 128 -129] | bits rol 1 --number-bytes 1 | math sum) == 253'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-number-bytes-runtime"
        category: "language-core"
        tags: [aggregate list bits ror number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-fixed-runtime"
        category: "language-core"
        tags: [aggregate list bits ror signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --signed --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-signed-i64-runtime"
        category: "language-core"
        tags: [scalar bits rol signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits rol 1 --signed --number-bytes 8) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits ror number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits ror 1 --number-bytes 1) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-unsigned-i64-left-u32-runtime"
        category: "language-core"
        tags: [scalar bits rol number-bytes runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.pid | bits rol 1 --number-bytes 8) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-default"
        category: "language-core"
        tags: [scalar bits rol ror default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((128 | bits rol 1) == 1) and ((-129 | bits rol 1) == -257) and ((4294967296 | bits ror 1) == 2147483648)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-default-runtime-reject"
        category: "language-core"
        tags: [scalar bits rol default runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits rol 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol default auto-width rotates require compile-time known integer input"
    }
]
