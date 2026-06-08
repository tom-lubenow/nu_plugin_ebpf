const VERIFIER_DIFF_FIXTURES_2126_2250 = [
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
    {
        name: "core-context-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-packet-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit packet reject]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.data | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-optval-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit cgroup-sockopt reject]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  $ctx.optval | emit'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-flow-keys-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit flow-dissector reject]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys | emit'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-histogram-rejects-pointer-escape"
        category: "language-core"
        tags: [context histogram reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | histogram'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-redirect-map-rejects-pointer-escape"
        category: "language-core"
        tags: [context redirect-map reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | redirect-map tx_ports --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-tail-call-rejects-pointer-escape"
        category: "language-core"
        tags: [context tail-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx | tail-call jumps'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-read-str-rejects-pointer-source"
        category: "language-core"
        tags: [context read-str reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | read-str'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-read-kernel-str-rejects-pointer-source"
        category: "language-core"
        tags: [context read-kernel-str reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | read-kernel-str'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-packet-rejects-pointer-delta"
        category: "language-core"
        tags: [context adjust-packet reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | adjust-packet --head'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-message-rejects-pointer-bytes"
        category: "language-core"
        tags: [context adjust-message reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx | adjust-message --apply'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-message-rejects-pointer-end"
        category: "language-core"
        tags: [context adjust-message reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 $ctx'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-redirect-rejects-pointer-ifindex"
        category: "language-core"
        tags: [context redirect reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | redirect'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-redirect-socket-rejects-pointer-key"
        category: "language-core"
        tags: [context redirect-socket reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx | redirect-socket peers --kind sockmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-assign-socket-rejects-pointer-socket"
        category: "language-core"
        tags: [context assign-socket reject]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx | assign-socket --replace'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-random-int-rejects-pipeline-input"
        category: "language-core"
        tags: [random reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | random int'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-map-define-rejects-pipeline-input"
        category: "language-core"
        tags: [maps map-define reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-define seen --kind hash --key-type u64 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-start-timer-rejects-pipeline-input"
        category: "language-core"
        tags: [timer reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | start-timer'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-stop-timer-rejects-pipeline-input"
        category: "language-core"
        tags: [timer reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | stop-timer'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-timer-allows-after-prior-statement"
        category: "language-core"
        tags: [timer accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  start-timer'
            '  stop-timer'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-map-put-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [maps map-put reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  map-put seen 0 --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put requires a value from pipeline input"
    }
    {
        name: "core-map-push-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [maps map-push reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  map-push recent --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-push requires a value from pipeline input"
    }
    {
        name: "core-global-set-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [global reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  global-set state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-set requires a value from pipeline input"
    }
    {
        name: "core-global-define-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [global reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  global-define state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define requires a compile-time constant value from pipeline input"
    }
    {
        name: "core-map-peek-rejects-pipeline-input"
        category: "language-core"
        tags: [maps queue map-peek reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind queue'
            '  let entry = ($ctx | map-peek recent_args --kind queue)'
            '  if $entry {'
            '    $entry.pid | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-map-pop-rejects-pipeline-input"
        category: "language-core"
        tags: [maps stack map-pop reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind stack'
            '  let entry = ($ctx | map-pop recent_args --kind stack)'
            '  if $entry {'
            '    $entry.cookie | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-context-map-get-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-get seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-map-delete-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-delete seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-map-contains-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-contains seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-map-get-rejects-pointer-key"
        category: "language-core"
        tags: [record context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-get seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-cgroup-array-contains-rejects-pointer-index"
        category: "language-core"
        tags: [record context map cgroup-array reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-contains cgroups --kind cgroup-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-map-put-rejects-pointer-escape"
        category: "language-core"
        tags: [record context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-put seen 0 --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-count-rejects-pointer-escape"
        category: "language-core"
        tags: [record context count reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [record context emit reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-packet-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [record context packet emit reject]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  { data: $ctx.data } | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-global-set-rejects-pointer-escape"
        category: "language-core"
        tags: [record context global reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | global-set state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-global-define-zero-rejects-pointer-escape"
        category: "language-core"
        tags: [record context global reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | global-define state --zero'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "adjust-packet-xdp-head"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-head-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --head 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-head-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --meta 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-meta-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta-subfn-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def shift [] {'
            '    adjust-packet --meta 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  shift'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-meta-subfn-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def shift [] {'
            '    adjust-packet --meta 0'
            '    0'
            '  }'
            '  shift'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-tail"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --tail 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-tail-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --tail 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-tail-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --tail 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-tc-action-room"
        category: "language-surface"
        tags: [adjust-packet tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-tc-action-room-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet tc-action packet-bounds reject]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --room 0 --mode 0'
            '  ($data | get 0) | count'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-tc-action-room-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet tc-action packet-bounds accept]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0'
            '  ($ctx.data | get 0) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-lwt-in-pull"
        category: "language-surface"
        tags: [adjust-packet lwt]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-lwt-xmit-head"
        category: "language-surface"
        tags: [adjust-packet lwt]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-xdp-ifindex"
        category: "language-surface"
        tags: [redirect xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-ifindex"
        category: "language-surface"
        tags: [redirect tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-peer"
        category: "language-surface"
        tags: [redirect peer tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-neigh"
        category: "language-surface"
        tags: [redirect neigh tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --neigh 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-egress-rejects-peer"
        category: "language-surface"
        tags: [redirect peer reject tc]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs"
    }
    {
        name: "redirect-tcx-egress-rejects-peer"
        category: "language-surface"
        tags: [redirect peer reject tcx]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs"
    }
    {
        name: "redirect-lwt-xmit-ifindex"
        category: "language-surface"
        tags: [redirect lwt]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-map-xdp-devmap"
        category: "language-surface"
        tags: [redirect-map xdp map]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-devmap-hash"
        category: "language-surface"
        tags: [redirect-map xdp map devmap-hash]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap-hash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-cpumap"
        category: "language-surface"
        tags: [redirect-map xdp map cpumap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map cpu_targets 0 --kind cpumap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-xskmap"
        category: "language-surface"
        tags: [redirect-map xdp map xskmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map xsks 0 --kind xskmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tail-call-prog-array"
        category: "language-surface"
        tags: [tail-call prog-array]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | tail-call jumps'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tail-call-helper-xdp-rejects-stale-data"
        category: "language-surface"
        tags: [tail-call xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_tail_call" $ctx jumps 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "emit-ringbuf-output-surface"
        category: "language-surface"
        tags: [emit ringbuf helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | emit'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "histogram-helper-surface"
        category: "language-surface"
        tags: [histogram map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  42 | histogram'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "start-timer-helper-surface"
        category: "language-surface"
        tags: [start-timer map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  start-timer'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stop-timer-helper-surface"
        category: "language-surface"
        tags: [stop-timer map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let delta = (stop-timer)'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "random-int-helper-surface"
        category: "language-surface"
        tags: [random helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = (random int)'
            '  $value | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "read-str-user-pointer"
        category: "language-surface"
        tags: [read-str helper metadata]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    $ptr | read-str --max-len 64 | emit'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "read-kernel-str-kernel-pointer"
        category: "language-surface"
        tags: [read-kernel-str helper metadata]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let task = (helper-call "bpf_get_current_task_btf")'
            '  $task.comm | read-kernel-str --max-len 16 | emit'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "assign-socket-sk-lookup-clear"
        category: "language-surface"
        tags: [assign-socket sk-lookup]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  assign-socket 0 --replace'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "assign-socket-tc-ingress-clear"
        category: "language-surface"
        tags: [assign-socket tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  assign-socket 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
