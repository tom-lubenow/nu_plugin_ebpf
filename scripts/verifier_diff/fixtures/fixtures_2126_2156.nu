const VERIFIER_DIFF_FIXTURES_2126_2156 = [
    {
        name: "core-record-spread-local"
        category: "language-core"
        tags: [aggregate record spread local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { pid: 7 }'
            '  let out = { ok: true, ...$rec }'
            '  $out.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-nested-field-local"
        category: "language-core"
        tags: [aggregate record nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { stats: { pid: 7 } }'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-local"
        category: "language-core"
        tags: [aggregate record upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = { pid: 7, msg: "hi" }'
            '  $rec.msg = "ok"'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-existing-nested-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = { stats: { pid: 0 } }'
            '  $rec.stats.pid = 7'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-nested-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.pid = 7'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-deep-nested-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.b.c = 7'
            '  $rec.a.b.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "core-record-upsert-new-nested-string-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.msg = "hi"'
            '  $rec.stats.msg | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-empty-record-nested-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = { stats: {} }'
            '  $rec.stats.pid = 7'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-field-local"
        category: "language-core"
        tags: [aggregate record upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.pid = 7'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-string-field-local"
        category: "language-core"
        tags: [aggregate record upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.msg = "hi"'
            '  $rec.msg | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-record-field-local"
        category: "language-core"
        tags: [aggregate record upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats = { pid: 7 }'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-return"
        category: "language-core"
        tags: [user-function aggregate record]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] { { pid: 7, msg: "hi" } }'
            '  let out = (make)'
            '  $out.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-return"
        category: "language-core"
        tags: [user-function aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = { msg: "hi" }'
            '    $rec.msg = "ok"'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.msg | count'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-field-return"
        category: "language-core"
        tags: [user-function aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.pid = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-string-field-return"
        category: "language-core"
        tags: [user-function aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.msg = "hi"'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.msg | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-nested-field-return"
        category: "language-core"
        tags: [user-function aggregate record upsert nested]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
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
        name: "core-user-function-record-upsert-new-list-field-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0 = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-numeric-list-append-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0 = 3'
            '    $rec.a.1 = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0 + $out.a.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-record-list-field-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0.b = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-record-list-element-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0 = { b: 3, c: 4 }'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.b + $out.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-record-list-new-element-field-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0.b = 3'
            '    $rec.a.0.c = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.b + $out.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-record-list-element-append-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0 = { b: 3, c: 4 }'
            '    $rec.a.1 = { b: 7, c: 8 }'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.c + $out.a.1.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
