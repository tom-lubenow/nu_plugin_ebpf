const VERIFIER_DIFF_FIXTURES_2157_2187_A = [
    {
        name: "core-user-function-record-upsert-record-list-append-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0.b = 3'
            '    $rec.a.1.b = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.b + $out.a.1.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-empty-record-nested-field-return"
        category: "language-core"
        tags: [user-function aggregate record upsert nested]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = { stats: {} }'
            '    $rec.stats.pid = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-context-arg"
        category: "language-core"
        tags: [user-function context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def read_pid [c] {'
            '    $c.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-parenthesized-context-arg"
        category: "language-core"
        tags: [user-function context accept source metadata]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def read_pid [c] {'
            '    $c.pid | count'
            '    0'
            '  }'
            '  let seen = (read_pid $ctx)'
            '  $seen | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-nested-context-arg"
        category: "language-core"
        tags: [user-function nested context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def read_pid [c] {'
            '    let actual = (id $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-deep-nested-context-arg"
        category: "language-core"
        tags: [user-function nested context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def id2 [x] { id $x }'
            '  def read_pid [c] {'
            '    let actual = (id2 $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-returned-context-alias"
        category: "language-core"
        tags: [user-function context source metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let actual = (id $ctx)'
            '  $actual.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-returned-parenthesized-context-alias"
        category: "language-core"
        tags: [user-function context source metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { ($x) }'
            '  let actual = (id ($ctx))'
            '  $actual.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
