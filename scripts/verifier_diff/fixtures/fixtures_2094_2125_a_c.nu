const VERIFIER_DIFF_FIXTURES_2094_2125_A_C = [
    {
        name: "core-record-insert-field"
        category: "language-core"
        tags: [aggregate record insert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | insert mem 9)'
            '  $rec.mem'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-update-field"
        category: "language-core"
        tags: [aggregate record update]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | update pid 9)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-missing-field"
        category: "language-core"
        tags: [aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | upsert mem 9)'
            '  $rec.mem'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-existing-field"
        category: "language-core"
        tags: [aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | upsert pid 9)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-insert-existing-reject"
        category: "language-core"
        tags: [aggregate record insert reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | insert pid 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "insert cannot replace existing record field 'pid'"
    }
    {
        name: "core-record-update-missing-reject"
        category: "language-core"
        tags: [aggregate record update reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | update mem 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "update cannot find record field 'mem'"
    }
]
