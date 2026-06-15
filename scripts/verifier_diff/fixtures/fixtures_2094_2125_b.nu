const VERIFIER_DIFF_FIXTURES_2094_2125_B = [
    {
        name: "core-null-default"
        category: "language-core"
        tags: ["null" default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  null | default 9'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-default-missing-field"
        category: "language-core"
        tags: [aggregate record default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 } | default 2 cpu)'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-default-null-field"
        category: "language-core"
        tags: [aggregate record default "null"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: null cpu: 2 } | default 7 pid)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-default-empty"
        category: "language-core"
        tags: [string default empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "" | default --empty "x" | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-upsert-local"
        category: "language-core"
        tags: [aggregate list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut xs = [1 2 3]'
            '  $xs.1 = 7'
            '  $xs.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-existing-index-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.0 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.1 = 7'
            '  $rec.a.0 + $rec.a.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-sparse-append-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.2 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only update an existing numeric list item or append at the next index"
    }
]
