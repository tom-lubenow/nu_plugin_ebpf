const VERIFIER_DIFF_FIXTURES_3803_3804 = [
    {
        name: "core-operator-not-in-accepts-runtime-string-needle"
        category: "language-core"
        tags: [operators not-in accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l not-in $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-operator-not-has-accepts-runtime-string-needle"
        category: "language-core"
        tags: [operators not-has accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l not-has $r'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
