const VERIFIER_DIFF_FIXTURES_3098_3098 = [
    {
        name: "core-record-transpose-rejects-as-record-flag"
        category: "records"
        tags: [records transpose diagnostics reject flag]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | transpose --as-record | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "transpose supports only the --ignore-titles flag for record input in eBPF"
    }
]
