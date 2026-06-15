const VERIFIER_DIFF_FIXTURES_2126_2156_B_B = [
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
