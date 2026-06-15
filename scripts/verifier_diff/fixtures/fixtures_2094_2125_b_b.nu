const VERIFIER_DIFF_FIXTURES_2094_2125_B_B = [
    {
        name: "core-record-upsert-new-record-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 7'
            '  $rec.a.0.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-record-list-element-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3, c: 4 }'
            '  $rec.a.0.b + $rec.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-new-element-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.0.c = 7'
            '  $rec.a.0.b + $rec.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.1.b = 7'
            '  $rec.a.0.b + $rec.a.1.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-element-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3, c: 4 }'
            '  $rec.a.1 = { b: 7, c: 8 }'
            '  $rec.a.0.b + $rec.a.1.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
