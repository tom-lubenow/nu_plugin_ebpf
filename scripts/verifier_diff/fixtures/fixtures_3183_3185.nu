const VERIFIER_DIFF_FIXTURES_3183_3185 = [
    {
        name: "core-runtime-string-is-empty"
        category: "language-core"
        tags: [string is-empty accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-runtime-string-is-not-empty"
        category: "language-core"
        tags: [string is-not-empty accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-runtime-string-length"
        category: "language-core"
        tags: [string length accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
