const VERIFIER_DIFF_FIXTURES_2219_2250_A_B = [
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
]
