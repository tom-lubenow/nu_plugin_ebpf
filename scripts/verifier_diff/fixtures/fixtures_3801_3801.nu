const VERIFIER_DIFF_FIXTURES_3801_3801 = [
    {
        name: "core-string-contains-accepts-runtime-input-substring"
        category: "language-core"
        tags: [string str contains accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l | str contains $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
