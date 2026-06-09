const VERIFIER_DIFF_FIXTURES_2867_2876 = [
    {
        name: "core-list-reverse-rejects-scalar-input"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject reverse input]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reverse requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-take-rejects-scalar-input"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject take input]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | take 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "take requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-skip-rejects-scalar-input"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject skip input]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | skip 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skip requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-drop-rejects-scalar-input"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject drop input]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | drop 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "drop requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-first-count-rejects-scalar-input"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject first input]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | first 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-last-count-rejects-scalar-input"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject last input]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | last 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last requires a stack-backed list input in eBPF"
    }
    {
        name: "core-list-take-rejects-dynamic-count"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject take count dynamic]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2] | take $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "take count must be a compile-time integer literal in eBPF"
    }
    {
        name: "core-list-skip-rejects-dynamic-count"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject skip count dynamic]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2] | skip $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skip count must be a compile-time integer literal in eBPF"
    }
    {
        name: "core-list-drop-rejects-dynamic-count"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject drop count dynamic]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2] | drop $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "drop count must be a compile-time integer literal in eBPF"
    }
    {
        name: "core-list-first-rejects-dynamic-count"
        category: "list-diagnostics"
        tags: [aggregate list diagnostics reject first count dynamic]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2] | first $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first count must be a compile-time integer literal in eBPF"
    }
]
