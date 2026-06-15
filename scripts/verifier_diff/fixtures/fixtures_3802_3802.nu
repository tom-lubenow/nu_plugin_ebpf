const VERIFIER_DIFF_FIXTURES_3802_3802 = [
    {
        name: "core-string-str-index-of-accepts-runtime-input-substring"
        category: "language-core"
        tags: [string str index-of accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l | str index-of $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
