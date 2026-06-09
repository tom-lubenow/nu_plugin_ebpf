const VERIFIER_DIFF_FIXTURES_2524_2530 = [
    {
        name: "core-string-split-words-rejects-dynamic-input"
        category: "language-core"
        tags: [string split words diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | split words'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split words requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-split-words-rejects-list-item-type"
        category: "language-core"
        tags: [string split words diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a b" 1] | split words'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split words requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-split-words-rejects-unconsumed-nested-list"
        category: "language-core"
        tags: [string split words diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a b" "c d"] | split words'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split words on list<string> produces nested lists, which require a metadata-only consumer in eBPF"
    }
    {
        name: "core-string-split-words-rejects-conflicting-flags"
        category: "language-core"
        tags: [string split words diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a b" | split words --min-word-length 1 --utf-8-bytes --grapheme-clusters'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split words accepts either --utf-8-bytes or --grapheme-clusters, not both, in eBPF"
    }
    {
        name: "core-string-split-words-rejects-measurement-flag-without-min"
        category: "language-core"
        tags: [string split words diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a b" | split words --grapheme-clusters'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split words --utf-8-bytes and --grapheme-clusters require --min-word-length in eBPF"
    }
    {
        name: "core-string-split-words-rejects-dynamic-min-word-length"
        category: "language-core"
        tags: [string split words diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a b" | split words --min-word-length $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split words --min-word-length requires a compile-time known integer in eBPF"
    }
    {
        name: "core-string-split-words-rejects-negative-min-word-length"
        category: "language-core"
        tags: [string split words diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a b" | split words --min-word-length -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split words --min-word-length requires a non-negative integer in eBPF"
    }
]
