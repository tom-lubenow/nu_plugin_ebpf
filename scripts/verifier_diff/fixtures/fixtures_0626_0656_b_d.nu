const VERIFIER_DIFF_FIXTURES_0626_0656_B_D = [
    {
        name: "tc-action-record-context-spread-write"
        category: "context-surface"
        tags: [tc-action context packet writable record spread source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-user-function-record-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable record user-function source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
