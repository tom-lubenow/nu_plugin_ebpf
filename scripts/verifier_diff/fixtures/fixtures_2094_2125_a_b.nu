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
    {
        name: "core-record-transpose-runtime-as-record-length-variants"
        category: "language-core"
        tags: [aggregate record transpose as-record ignore-titles length accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let default_len = ({ pid: $ctx.pid cpu: 7 } | transpose --as-record | length)'
            '  let custom_len = ({ pid: $ctx.pid cpu: 7 } | transpose --as-record key value | length)'
            '  let ignored_len = ({ pid: $ctx.pid cpu: 7 } | transpose --as-record --ignore-titles val | length)'
            '  ($default_len == 2) and (($custom_len == 2) and ($ignored_len == 1))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-runtime-as-record-empty-predicates"
        category: "language-core"
        tags: [aggregate record transpose as-record is-empty is-not-empty accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let default_empty = ({ pid: $ctx.pid cpu: 7 } | transpose --as-record | is-empty)'
            '  let ignored_not_empty = ({ pid: $ctx.pid cpu: 7 } | transpose --as-record --ignore-titles val | is-not-empty)'
            '  ($default_empty == false) and ($ignored_not_empty == true)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-runtime-direct-row-projection"
        category: "language-core"
        tags: [aggregate record transpose get accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let value = ({ pid: $ctx.pid cpu: 7 } | transpose key value | get 1 | get value)'
            '  let key_ok = ({ pid: $ctx.pid cpu: 7 } | transpose key value | get 0 | get key | str starts-with "pid")'
            '  let ignored = ({ pid: $ctx.pid cpu: 7 } | transpose --ignore-titles val | get 1 | get val)'
            '  ($value == 7) and ($key_ok and ($ignored == 7))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
