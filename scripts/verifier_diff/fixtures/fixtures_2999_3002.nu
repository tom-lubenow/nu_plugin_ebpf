const VERIFIER_DIFF_FIXTURES_2999_3002 = [
    {
        name: "core-list-sort-rejects-natural-flag"
        category: "language-core"
        tags: [list sort diagnostics reject flag]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | sort --natural'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort --natural is not supported for stack-backed numeric lists in eBPF"
    }
    {
        name: "core-list-sort-rejects-values-flag"
        category: "language-core"
        tags: [list sort diagnostics reject flag]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {b: 4 a: 3} | sort --values'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort --values is not supported for stack-backed numeric lists in eBPF"
    }
    {
        name: "core-list-split-list-rejects-invalid-split-mode"
        category: "language-core"
        tags: [list split diagnostics reject mode]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | split list --split sideways 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list --split must be 'on', 'before', or 'after' in eBPF, got 'sideways'"
    }
    {
        name: "core-list-split-list-regex-rejects-nested-list-item"
        category: "language-core"
        tags: [list split regex diagnostics reject nested]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [[1] abc] | split list --regex "1"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list --regex supports only string, int, bool, null, filesize, and duration compile-time list items in eBPF; got list<int>"
    }
]
