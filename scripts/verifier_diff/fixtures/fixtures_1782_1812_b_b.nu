const VERIFIER_DIFF_FIXTURES_1782_1812_B_B = [
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
        name: "core-list-bits-not-runtime-masked-default"
        category: "language-core"
        tags: [aggregate list bits "not" runtime number-bytes default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([(random int)] | bits not --number-bytes 1 | length) == 1) and (([(random int)] | bits not | length) == 1)'
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
