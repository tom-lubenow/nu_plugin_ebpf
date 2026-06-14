const VERIFIER_DIFF_FIXTURES_2219_2250_A = [
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
]
