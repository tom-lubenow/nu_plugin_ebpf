const VERIFIER_DIFF_FIXTURES_1813_1843_B_C = [
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
        name: "core-list-bits-rotate-default-zero-runtime"
        category: "language-core"
        tags: [aggregate list bits rol ror default runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([(random int)] | bits rol 0 | length) == 1) and (([(random int)] | bits ror 0 | length) == 1)'
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
