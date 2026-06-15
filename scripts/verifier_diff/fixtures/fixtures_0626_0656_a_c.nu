const VERIFIER_DIFF_FIXTURES_0626_0656_A_C = [
    {
        name: "tc-record-socket-context-get-root"
        category: "context-surface"
        tags: [tc context socket record get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  let sk = ($rec | get socket)'
            '  $sk.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-get-chain"
        category: "context-surface"
        tags: [tc context socket record get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  $rec | get socket | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-rename-get-chain"
        category: "context-surface"
        tags: [tc context socket record rename get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { ok: true, socket: $ctx.sk }'
            '  $rec | rename keep sock | get sock | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-wrapper-get-chain"
        category: "context-surface"
        tags: [tc context socket record wrapper get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { socket: $sock } }'
            '  wrap $ctx.sk | get socket | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
