const VERIFIER_DIFF_FIXTURES_2094_2125_B_C = [
    {
        name: "core-record-upsert-record-list-heterogeneous-append-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.1.c = 7'
            '  $rec.a.1.c'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only append homogeneous fixed record array elements"
    }
    {
        name: "core-record-upsert-record-list-element-append-mismatch-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3 }'
            '  $rec.a.1 = { b: 7, c: 8 }'
            '  $rec.a.1.b'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only append homogeneous fixed record array elements"
    }
]
