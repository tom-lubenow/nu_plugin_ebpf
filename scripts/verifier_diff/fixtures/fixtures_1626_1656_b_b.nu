const VERIFIER_DIFF_FIXTURES_1626_1656_B_B = [
    {
        name: "core-null-compare-flow"
        category: "language-core"
        tags: [control-flow "null"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let maybe = null'
            '  if $maybe == null { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-spread"
        category: "language-core"
        tags: [aggregate list spread]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let xs = [1, 2]'
            '  let ys = [0, ...$xs, 3]'
            '  $ys | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-first-scalar"
        category: "language-core"
        tags: [aggregate list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-last-scalar"
        category: "language-core"
        tags: [aggregate list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-first-empty-reject"
        category: "language-core"
        tags: [aggregate list first reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | first'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first requires a stack-backed numeric list with proven non-empty length"
    }
    {
        name: "core-list-last-empty-reject"
        category: "language-core"
        tags: [aggregate list last reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | last'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last requires a stack-backed numeric list with proven non-empty length"
    }
    {
        name: "core-list-first-count"
        category: "language-core"
        tags: [aggregate list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first 2 | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-last-count"
        category: "language-core"
        tags: [aggregate list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
