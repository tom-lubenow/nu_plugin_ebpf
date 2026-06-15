const VERIFIER_DIFF_FIXTURES_2157_2187_B = [
    {
        name: "core-user-function-record-context-upsert-new-field-access"
        category: "language-core"
        tags: [user-function record context upsert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] {'
            '    mut rec = {}'
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
    {
        name: "core-user-function-record-context-spread-field-access"
        category: "language-core"
        tags: [user-function record context spread accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] {'
            '    let base = { k: $x }'
            '    let rec = { ok: true, ...$base }'
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
    {
        name: "core-user-function-record-context-direct-spread-return"
        category: "language-core"
        tags: [user-function record context spread accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] {'
            '    let base = { k: $x }'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-nested-record-context-spread"
        category: "language-core"
        tags: [user-function record context spread nested source metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] { { k: $x } }'
            '  def outer [x] {'
            '    let base = (wrap $x)'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (outer $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
