const VERIFIER_DIFF_FIXTURES_3179_3182 = [
    {
        name: "core-string-length-accepts-runtime-input"
        category: "language-core"
        tags: [string str length accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str length'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-string-length-accepts-runtime-input-utf8-bytes"
        category: "language-core"
        tags: [string str length accept runtime utf8]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str length --utf-8-bytes'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-string-length-rejects-runtime-input-chars"
        category: "language-core"
        tags: [string str length diagnostics reject runtime chars]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str length --chars'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str length requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-length-rejects-runtime-input-grapheme-clusters"
        category: "language-core"
        tags: [string str length diagnostics reject runtime grapheme]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str length --grapheme-clusters'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str length requires compile-time known string input in eBPF"
    }
]
