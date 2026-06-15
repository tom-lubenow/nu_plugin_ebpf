const VERIFIER_DIFF_FIXTURES_3828_3828 = [
    {
        name: "core-list-bool-slices-accept-bounded-runtime-count"
        category: "list-diagnostics"
        tags: [aggregate list bool take first skip drop last count runtime accept]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  let n = random int 0..3'
            '  let take_len = ([true false true] | take $n | length)'
            '  let first_len = ([true false true] | first $n | length)'
            '  let skip_len = ([true false true] | skip $n | length)'
            '  let drop_len = ([true false true] | drop $n | length)'
            '  let last_len = ([true false true] | last $n | length)'
            '  (((($take_len <= 3) and ($first_len <= 3)) and (($skip_len <= 3) and ($drop_len <= 3))) and ($last_len <= 3))'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
