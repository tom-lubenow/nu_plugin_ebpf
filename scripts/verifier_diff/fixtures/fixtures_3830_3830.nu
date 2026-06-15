const VERIFIER_DIFF_FIXTURES_3830_3830 = [
    {
        name: "core-list-append-prepend-accept-runtime-bool-item"
        category: "list-diagnostics"
        tags: [aggregate list bool append prepend runtime accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  let item = ((random int) > 0)'
            '  let appended = ([true false] | append $item | length)'
            '  let prepended = ([true false] | prepend $item | length)'
            '  ($appended == 3) and ($prepended == 3)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
