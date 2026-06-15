const VERIFIER_DIFF_FIXTURES_3829_3829 = [
    {
        name: "core-list-find-accepts-runtime-bool-needle"
        category: "list-diagnostics"
        tags: [aggregate list bool find runtime accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  let needle = ((random int) > 0)'
            '  [true false true] | find $needle | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
