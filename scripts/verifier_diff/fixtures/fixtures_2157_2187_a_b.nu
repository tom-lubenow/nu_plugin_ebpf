const VERIFIER_DIFF_FIXTURES_2157_2187_A_B = [
    {
        name: "core-record-context-field-access"
        category: "language-core"
        tags: [record context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { k: $ctx }'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-identity-wrapped-context-field-access"
        category: "language-core"
        tags: [record user-function context source metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let rec = { event: (id $ctx) }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-context-upsert-field-access"
        category: "language-core"
        tags: [record context upsert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = { k: null }'
            '  $rec.k = $ctx'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-context-upsert-new-field-access"
        category: "language-core"
        tags: [record context upsert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.k = $ctx'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-context-spread-field-access"
        category: "language-core"
        tags: [record context spread accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let base = { k: $ctx }'
            '  let rec = { ok: true, ...$base }'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-context-field-access"
        category: "language-core"
        tags: [user-function record context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] { { k: $x } }'
            '  let rec = (wrap $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-context-upsert-field-access"
        category: "language-core"
        tags: [user-function record context upsert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] {'
            '    mut rec = { k: null }'
            '    $rec.k = $x'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
