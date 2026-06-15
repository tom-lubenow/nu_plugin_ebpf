const VERIFIER_DIFF_FIXTURES_2538_2545 = [
    {
        name: "core-string-str-index-of-rejects-extra-substring"
        category: "language-core"
        tags: [string str index-of diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str index-of "a" "b"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str index-of accepts exactly one substring argument in eBPF"
    }
    {
        name: "core-string-str-index-of-accepts-dynamic-substring"
        category: "language-core"
        tags: [string str index-of accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str index-of $ctx.comm'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-string-str-index-of-nul-substring"
        category: "language-core"
        tags: [string str index-of nul accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str index-of "a\u{0000}"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-index-of-rejects-conflicting-flags"
        category: "language-core"
        tags: [string str index-of diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str index-of --utf-8-bytes --grapheme-clusters "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str index-of accepts either --utf-8-bytes or --grapheme-clusters, not both, in eBPF"
    }
    {
        name: "core-string-str-index-of-rejects-dynamic-range"
        category: "language-core"
        tags: [string str index-of range diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str index-of "a" --range $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str index-of --range requires a compile-time known range in eBPF"
    }
    {
        name: "core-string-str-index-of-rejects-grapheme-range-boundary"
        category: "language-core"
        tags: [string str index-of grapheme range diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "éa" | str index-of --grapheme-clusters "a" --range 1..3'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str index-of --grapheme-clusters --range bounds must align to UTF-8 character boundaries in eBPF"
    }
    {
        name: "core-string-str-index-of-accepts-context-comm-input"
        category: "language-core"
        tags: [string str index-of accept runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str index-of "a"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-index-of-rejects-list-item-type"
        category: "language-core"
        tags: [string str index-of diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" 1] | str index-of "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str index-of requires string list items in eBPF; item 1 has type int"
    }
]
