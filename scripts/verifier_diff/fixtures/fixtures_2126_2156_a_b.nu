const VERIFIER_DIFF_FIXTURES_2126_2156_A_B = [
    {
        name: "core-record-upsert-new-nested-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.values.0 = 7'
            '  $rec.stats.values.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-nested-numeric-list-existing-index-local"
        category: "language-core"
        tags: [aggregate record list upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.values.0 = 3'
            '  $rec.stats.values.0 = 7'
            '  $rec.stats.values.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-nested-numeric-list-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.values.0 = 3'
            '  $rec.stats.values.1 = 7'
            '  $rec.stats.values.0 + $rec.stats.values.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-annotated-record-array-nested-numeric-list-upsert-local"
        category: "language-core"
        tags: [aggregate record list upsert nested annotated local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rows: list<record<samples: list<int>>> = [{samples: [1 2]} {samples: [3 4]}]'
            '  $rows.1.samples.1 = 9'
            '  $rows.1.samples.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
