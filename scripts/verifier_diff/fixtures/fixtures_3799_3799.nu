const VERIFIER_DIFF_FIXTURES_3799_3799 = [
    {
        name: "core-string-ends-with-accepts-runtime-input-suffix"
        category: "language-core"
        tags: [string str ends-with accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l | str ends-with $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
