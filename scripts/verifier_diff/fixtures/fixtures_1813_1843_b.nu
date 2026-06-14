const VERIFIER_DIFF_FIXTURES_1813_1843_B = [
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
        name: "core-scalar-bits-shift-default-runtime"
        category: "language-core"
        tags: [scalar bits shl default runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shl 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
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
        name: "core-list-bits-rotate-default"
        category: "language-core"
        tags: [aggregate list bits rol ror default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([127 128 -129 256] | bits rol 1 | math sum) == 510) and (([1 256 -129 4294967296] | bits ror 1 | math sum) == 2147483839)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-default-runtime"
        category: "language-core"
        tags: [scalar bits rol default runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits rol 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
