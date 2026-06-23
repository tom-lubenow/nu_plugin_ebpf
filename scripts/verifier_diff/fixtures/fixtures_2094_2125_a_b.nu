const VERIFIER_DIFF_FIXTURES_2094_2125_A_B = [
    {
        name: "core-runtime-list-describe"
        category: "language-core"
        tags: [describe aggregate list runtime string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  seq 10 10 20 | append $n | describe | str starts-with "list<int>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-heterogeneous-reject"
        category: "language-core"
        tags: [aggregate record values reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: "nu" } | values'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "values supports only integer-like, bool, or null scalar record fields"
    }
    {
        name: "core-record-values-mixed-math-mode-reject"
        category: "language-core"
        tags: [aggregate record values math mode reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: "nu" } | values | math mode | str join "-"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math mode requires"
    }
    {
        name: "core-record-transpose-runtime-reject"
        category: "language-core"
        tags: [aggregate record transpose reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid } | transpose key value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "transpose requires compile-time known record values"
    }
    {
        name: "core-record-transpose-runtime-length"
        category: "language-core"
        tags: [aggregate record transpose length accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ({ pid: $ctx.pid cpu: 7 } | transpose key value | length) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-runtime-is-empty"
        category: "language-core"
        tags: [aggregate record transpose is-empty accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ({ pid: $ctx.pid cpu: 7 } | transpose key value | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-runtime-is-not-empty"
        category: "language-core"
        tags: [aggregate record transpose is-not-empty accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ({ pid: $ctx.pid cpu: 7 } | transpose key value | is-not-empty) == true'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
