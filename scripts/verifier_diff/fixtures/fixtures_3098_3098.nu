const VERIFIER_DIFF_FIXTURES_3098_3098 = [
    {
        name: "core-record-transpose-as-record"
        category: "records"
        tags: [records transpose as-record accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | transpose --as-record | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
