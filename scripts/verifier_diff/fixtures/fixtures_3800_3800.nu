const VERIFIER_DIFF_FIXTURES_3800_3800 = [
    {
        name: "core-operator-not-ends-with-accepts-runtime-suffix"
        category: "language-core"
        tags: [operators not-ends-with accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l not-ends-with $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
