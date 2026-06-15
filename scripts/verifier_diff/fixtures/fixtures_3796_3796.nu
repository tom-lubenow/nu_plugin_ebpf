const VERIFIER_DIFF_FIXTURES_3796_3796 = [
    {
        name: "core-operator-string-inequality-accepts-two-runtime-strings"
        category: "language-core"
        tags: [operators string-inequality accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l != $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
