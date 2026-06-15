const VERIFIER_DIFF_FIXTURES_2126_2156_A = [
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
]
