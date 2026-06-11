const VERIFIER_DIFF_FIXTURES_2877_2886 = [
    {
        name: "core-list-last-rejects-dynamic-count"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject last count dynamic]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2] | last $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last count must be a compile-time integer literal in eBPF"
    }
    {
        name: "core-list-uniq-rejects-count-flag"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject uniq flag]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2] | uniq --count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "uniq does not accept arguments in eBPF"
    }
    {
        name: "core-list-sort-ignore-case-numeric"
        category: "list-diagnostics"
        tags: [aggregate list sort ignore-case accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2] | sort --ignore-case | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all-rejects-scalar-input"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject all input]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | all {|x| $x > 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "all requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-any-rejects-scalar-input"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject any input]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | any {|x| $x > 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "any requires a stack-backed list input in eBPF"
    }
    {
        name: "core-math-arccos-rejects-out-of-domain-list-item"
        category: "language-core"
        tags: [math arccos diagnostics reject list domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [2] | math arccos'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arccos requires list items in the closed interval [-1, 1] in eBPF; item 0 is 2"
    }
    {
        name: "core-math-arcsin-rejects-out-of-domain-input"
        category: "language-core"
        tags: [math arcsin diagnostics reject input domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  2 | math arcsin'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arcsin requires input in the closed interval [-1, 1] in eBPF; input is 2"
    }
    {
        name: "core-math-arccosh-rejects-low-input"
        category: "language-core"
        tags: [math arccosh diagnostics reject input domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0 | math arccosh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arccosh requires input >= 1 in eBPF; input is 0"
    }
    {
        name: "core-math-arccosh-rejects-low-list-item"
        category: "language-core"
        tags: [math arccosh diagnostics reject list domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0] | math arccosh'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math arccosh requires list items >= 1 in eBPF; item 0 is 0"
    }
    {
        name: "core-math-sqrt-rejects-negative-list-item"
        category: "language-core"
        tags: [math sqrt diagnostics reject list domain]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [-1] | math sqrt'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sqrt requires non-negative list items in eBPF; item 0 is -1"
    }
]
