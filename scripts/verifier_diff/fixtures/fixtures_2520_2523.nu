const VERIFIER_DIFF_FIXTURES_2520_2523 = [
    {
        name: "core-string-split-chars-rejects-dynamic-input"
        category: "language-core"
        tags: [string split chars diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | split chars'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split chars requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-split-chars-rejects-list-item-type"
        category: "language-core"
        tags: [string split chars diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" 1] | split chars'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split chars requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-split-chars-rejects-conflicting-flags"
        category: "language-core"
        tags: [string split chars diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | split chars --code-points --grapheme-clusters'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split chars accepts either --code-points or --grapheme-clusters, not both, in eBPF"
    }
    {
        name: "core-string-split-chars-rejects-unconsumed-nested-list"
        category: "language-core"
        tags: [string split chars diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | split chars'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split chars on list<string> produces nested lists, which require a metadata-only consumer in eBPF"
    }
]
