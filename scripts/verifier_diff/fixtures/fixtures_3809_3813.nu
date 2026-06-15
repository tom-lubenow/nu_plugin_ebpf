const VERIFIER_DIFF_FIXTURES_3809_3813 = [
    {
        name: "core-list-take-accepts-bounded-runtime-count"
        category: "list-diagnostics"
        tags: [aggregate list take count runtime accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | take (random int 0..3) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-list-first-accepts-bounded-runtime-count"
        category: "list-diagnostics"
        tags: [aggregate list first count runtime accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | first (random int 0..3) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-list-skip-accepts-bounded-runtime-count"
        category: "list-diagnostics"
        tags: [aggregate list skip count runtime accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | skip (random int 0..3) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-list-drop-accepts-bounded-runtime-count"
        category: "list-diagnostics"
        tags: [aggregate list drop count runtime accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | drop (random int 0..3) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-list-last-accepts-bounded-runtime-count"
        category: "list-diagnostics"
        tags: [aggregate list last count runtime accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | last (random int 0..3) | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
