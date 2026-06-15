const VERIFIER_DIFF_FIXTURES_1032_1062_B_D = [
    {
        name: "lwt-xmit-rejects-tstamp-context"
        category: "context-policy"
        tags: [lwt reject context timestamp]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.tstamp | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "lwt-xmit-rejects-sk-assignment"
        category: "context-policy"
        tags: [lwt reject context writable socket]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available"
    }
]
