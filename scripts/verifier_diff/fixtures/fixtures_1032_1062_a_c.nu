const VERIFIER_DIFF_FIXTURES_1032_1062_A_C = [
    {
        name: "lwt-xmit-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.priority + $ctx.cb.3) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.mark) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.cb.1 = 7'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-record-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable record source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut rec = { data: $ctx.data }'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
