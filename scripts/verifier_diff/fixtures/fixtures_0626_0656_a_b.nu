const VERIFIER_DIFF_FIXTURES_0626_0656_A_B = [
    {
        name: "tc-record-socket-context-pipeline-upsert"
        category: "context-surface"
        tags: [tc context socket record upsert source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | upsert socket $ctx.sk)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-pipeline-preserve"
        category: "context-surface"
        tags: [tc context socket record upsert preserve source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ($base | upsert ok true)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-pipeline-shape"
        category: "context-surface"
        tags: [tc context socket record merge select reject rename source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk, keep: 1 } | merge { ok: true } | select socket ok | reject ok | rename sock)'
            '  $rec.sock.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-default-field"
        category: "context-surface"
        tags: [tc context socket record default source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default $ctx.sk socket)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-spread-pipeline-rename"
        category: "context-surface"
        tags: [tc context socket record spread rename source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ({ ...$base } | rename sock)'
            '  $rec.sock.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
