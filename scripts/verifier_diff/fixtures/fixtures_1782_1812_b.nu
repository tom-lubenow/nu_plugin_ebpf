const VERIFIER_DIFF_FIXTURES_1782_1812_B = [
    {
        name: "core-scalar-bits-binary-runtime"
        category: "language-core"
        tags: [scalar bits and or xor runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((random int | bits and 3) + (random int | bits or 2) + (random int | bits xor 1)) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary"
        category: "language-core"
        tags: [aggregate list bits and or xor]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits and 2 | bits or 8 | bits xor 1 | math sum) == 31'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-runtime"
        category: "language-core"
        tags: [aggregate list bits and or xor runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits and 3 | bits or 4 | bits xor 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits and or xor endian]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[ab cd] | bits and 0x[99 99] | bytes starts-with 0x[89 89]) and (0x[c0 ff ee] | bits or 0x[ff] --endian big | bytes starts-with 0x[c0 ff ff]) and (0x[ff] | bits xor 0x[12 34 56] --endian little | bytes starts-with 0x[ed 34 56])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits xor bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[aa] 0x[bb cc]] | bits xor 0x[ff] | bytes collect | bytes length) == 3) and (([0x[aa] 0x[bb cc]] | bits xor 0x[ff] | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-get-fold"
        category: "language-core"
        tags: [aggregate list binary bits xor get bytes starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01] 0x[02 03]] | bits xor 0x[ff] | get 1 | bytes starts-with 0x[fd fc]) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-describe-fold"
        category: "language-core"
        tags: [aggregate list binary bits xor describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bits xor 0x[ff] --endian big | describe | str starts-with "list<binary>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-metadata-predicates"
        category: "language-core"
        tags: [aggregate list binary bits and xor length predicates metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((([0x[] 0x[]] | bits and 0x[ff] | length) == 2) and ([0x[] 0x[]] | bits and 0x[ff] | is-not-empty)) and ([0x[01] 0x[02 03]] | bits xor 0x[ff] --endian big | is-not-empty)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-signed"
        category: "language-core"
        tags: [scalar bits "not" signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (4 | bits not --signed) == -5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-signed-number-bytes"
        category: "language-core"
        tags: [scalar bits "not" signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((4 | bits not --signed --number-bytes 1) == -5) and ((4 | bits not --signed --number-bytes 2) == -5)) and (((4 | bits not --signed --number-bytes 4) == -5) and ((4 | bits not --signed --number-bytes 8) == -5))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-signed-runtime"
        category: "language-core"
        tags: [scalar bits "not" signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits not --signed) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits "not" number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits not --number-bytes 1) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-signed"
        category: "language-core"
        tags: [aggregate list bits "not" signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits not --signed | math sum) == -12'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-signed-runtime"
        category: "language-core"
        tags: [aggregate list bits "not" signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits not --signed | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-default-runtime"
        category: "language-core"
        tags: [scalar bits "not" default runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  random int | bits not'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-default"
        category: "language-core"
        tags: [scalar bits "not"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits not) == 251) and ((256 | bits not) == 65279) and ((65536 | bits not) == 4294901759) and ((4294967296 | bits not) == 140733193388031)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-number-bytes"
        category: "language-core"
        tags: [scalar bits "not" number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits not --number-bytes 8) == 140737488355323) and ((-130 | bits not --number-bytes 1) == 129)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits "not" signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[ff 00 7f] | bits not | bytes starts-with 0x[00 ff 80]) and (0x[aa 55] | bits not --number-bytes 8 | bytes starts-with 0x[55 aa]) and (0x[c3] | bits not --signed --number-bytes 8 | bytes starts-with 0x[3c])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[ff] 0x[00 01]] | bits not | bytes collect | bytes length) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
