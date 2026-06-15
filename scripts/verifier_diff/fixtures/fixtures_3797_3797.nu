const VERIFIER_DIFF_FIXTURES_3797_3797 = [
    {
        name: "core-operator-not-starts-with-accepts-runtime-prefix"
        category: "language-core"
        tags: [operators not-starts-with accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l not-starts-with $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
