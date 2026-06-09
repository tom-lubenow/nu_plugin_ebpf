const VERIFIER_DIFF_FIXTURES_2579_2586 = [
    {
        name: "core-list-split-list-regex-rejects-binary-item"
        category: "language-core"
        tags: [list split-list regex binary diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[0102]] | split list --regex "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list --regex supports only string, int, bool, null, filesize, and duration compile-time list items in eBPF; got binary"
    }
    {
        name: "core-list-split-list-rejects-dynamic-input"
        category: "language-core"
        tags: [list split-list diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | split list "n"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list requires a compile-time known list pipeline input in eBPF"
    }
    {
        name: "core-list-split-list-rejects-dynamic-separator"
        category: "language-core"
        tags: [list split-list diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | split list $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list separator must be compile-time known in eBPF"
    }
    {
        name: "core-list-split-list-regex-rejects-non-string-separator"
        category: "language-core"
        tags: [list split-list regex diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | split list --regex 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list --regex separator must be a compile-time string in eBPF; got int"
    }
    {
        name: "core-list-split-list-regex-rejects-invalid-pattern"
        category: "language-core"
        tags: [list split-list regex diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b"] | split list --regex "["'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list --regex pattern is invalid in eBPF"
    }
    {
        name: "core-list-split-list-regex-rejects-record-item"
        category: "language-core"
        tags: [list split-list regex record diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [{a: 1}] | split list --regex "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list --regex supports only string, int, bool, null, filesize, and duration compile-time list items in eBPF; got record"
    }
    {
        name: "core-list-split-list-split-rejects-dynamic-mode"
        category: "language-core"
        tags: [list split-list split diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | split list --split $ctx.comm 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list --split requires a compile-time known string in eBPF"
    }
    {
        name: "core-list-split-list-split-rejects-invalid-mode"
        category: "language-core"
        tags: [list split-list split diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | split list --split middle 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list --split must be 'on', 'before', or 'after' in eBPF, got 'middle'"
    }
]
