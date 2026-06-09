const VERIFIER_DIFF_FIXTURES_2546_2551 = [
    {
        name: "core-string-str-substring-rejects-extra-rest-argument"
        category: "language-core"
        tags: [string str substring diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str substring 0..1 name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str substring requires exactly one explicit range argument in eBPF"
    }
    {
        name: "core-string-str-substring-rejects-dynamic-range"
        category: "language-core"
        tags: [string str substring diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str substring $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str substring requires a compile-time known range argument in eBPF"
    }
    {
        name: "core-string-str-substring-rejects-conflicting-flags"
        category: "language-core"
        tags: [string str substring diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str substring --utf-8-bytes --grapheme-clusters 0..1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str substring accepts either --utf-8-bytes or --grapheme-clusters, not both, in eBPF"
    }
    {
        name: "core-string-str-substring-rejects-dynamic-input"
        category: "language-core"
        tags: [string str substring diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str substring 0..1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str substring requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-str-substring-rejects-list-item-type"
        category: "language-core"
        tags: [string str substring diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" 1] | str substring 0..1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str substring requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-str-substring-rejects-byte-range-splitting-utf8"
        category: "language-core"
        tags: [string str substring diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "éa" | str substring 1..2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str substring byte bounds must preserve valid UTF-8 in eBPF"
    }
]
