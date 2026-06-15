const VERIFIER_DIFF_FIXTURES_2126_2156_A_C = [
    {
        name: "core-annotated-record-array-nested-string-field-local"
        category: "language-core"
        tags: [aggregate record string nested annotated local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rows: list<record<name: string>> = [{name: "aa"} {name: "bb"}]'
            '  $rows.1.name | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-annotated-record-array-nested-string-upsert-local"
        category: "language-core"
        tags: [aggregate record string upsert nested annotated local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rows: list<record<name: string>> = [{name: "aa"} {name: "bb"}]'
            '  $rows.1.name = "cc"'
            '  $rows.1.name | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-annotated-bool-fixed-array-upsert-local"
        category: "language-core"
        tags: [aggregate fixed-array bool upsert annotated local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut flags: list<bool> = [true false]'
            '  $flags.1 = true'
            '  if $flags.1 { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-nested-numeric-list-sparse-append-reject"
        category: "language-core"
        tags: [aggregate record list upsert append nested reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.values.0 = 3'
            '  $rec.stats.values.2 = 7'
            '  $rec.stats.values.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only update an existing numeric list item or append at the next index"
    }
    {
        name: "core-record-upsert-new-nested-record-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.rows.0.pid = 7'
            '  $rec.stats.rows.0.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
