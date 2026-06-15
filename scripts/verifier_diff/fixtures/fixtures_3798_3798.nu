const VERIFIER_DIFF_FIXTURES_3798_3798 = [
    {
        name: "core-string-starts-with-accepts-runtime-input-prefix"
        category: "language-core"
        tags: [string str starts-with accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l | str starts-with $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
