const VERIFIER_DIFF_FIXTURES_3823_3824 = [
    {
        name: "core-get-string-list-accepts-range-proven-runtime-index"
        category: "language-core"
        tags: [aggregate list get string accept runtime runtime-index]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | get (random int 0..1) | str starts-with "a"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-get-integer-list-accepts-range-proven-runtime-index"
        category: "language-core"
        tags: [aggregate list get integer accept runtime runtime-index]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([10 20] | get (random int 0..1)) > 0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
