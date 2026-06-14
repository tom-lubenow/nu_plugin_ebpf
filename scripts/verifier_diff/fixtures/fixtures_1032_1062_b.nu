const VERIFIER_DIFF_FIXTURES_1032_1062_B = [
    {
        name: "lwt-xmit-record-spread-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable record spread source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let base = { data: $ctx.data }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-user-function-record-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable user-function record source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  def wrap [data] { { data: $data } }'
            '  mut rec = (wrap $ctx.data)'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-metadata-context-write"
        category: "context-surface"
        tags: [lwt context writable source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  $ctx.cb.2 = 9'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-rejects-packet-data-write"
        category: "context-policy"
        tags: [lwt reject context packet writable]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "direct packet writes are not supported on lwt_in programs"
    }
    {
        name: "lwt-in-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.ingress_ifindex + $ctx.mark) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.0) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-context-write"
        category: "context-surface"
        tags: [lwt context writable]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.queue_mapping + $ctx.protocol + $ctx.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.2) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-context-write"
        category: "context-surface"
        tags: [lwt context writable]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-rejects-csum-level-context"
        category: "context-policy"
        tags: [lwt reject context helper-backed]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.csum_level | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.csum_level is only available on lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "lwt-seg6local-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.hash + $ctx.route_realm + $ctx.gso_size) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.4) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-context-write"
        category: "context-surface"
        tags: [lwt context writable seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb.4 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
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
