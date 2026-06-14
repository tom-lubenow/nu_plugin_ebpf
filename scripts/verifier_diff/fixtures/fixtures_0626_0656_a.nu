const VERIFIER_DIFF_FIXTURES_0626_0656_A = [
    {
        name: "xdp-cgroup-array-contains"
        category: "packet"
        tags: [xdp cgroup-array helper-policy]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-context"
        category: "context-surface"
        tags: [tc-action context packet]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-rich-metadata-context"
        category: "context-surface"
        tags: [tc-action context packet source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.wire_len + $ctx.gso_segs + $ctx.gso_size + $ctx.tc_index + $ctx.tstamp + $ctx.tstamp_type + $ctx.hwtstamp + $ctx.cb.0) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.2 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable record source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-upsert-write"
        category: "context-surface"
        tags: [tc-action context packet writable record upsert source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
