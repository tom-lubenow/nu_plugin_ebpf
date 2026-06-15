const VERIFIER_DIFF_FIXTURES_0813_0843_A = [
    {
        name: "socket-filter-cb-context-write"
        category: "context-surface"
        tags: [socket-filter context writable]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb.1 = 7'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "socket-filter-rejects-mark-context-write"
        category: "context-policy"
        tags: [socket-filter context writable reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is read-only"
    }
    {
        name: "cgroup-skb-egress-context"
        category: "context-surface"
        tags: [cgroup-skb context]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.remote_ip4 + $ctx.local_port + $ctx.sk.cgroup_id + $ctx.sk.ancestor_cgroup_id.0) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-rich-egress-context"
        category: "context-surface"
        tags: [cgroup-skb context egress source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.tc_index + $ctx.hash + $ctx.tstamp + $ctx.hwtstamp) | count'
            '  (($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 1) + $ctx.family + $ctx.socket_cookie + $ctx.socket_uid + $ctx.netns_cookie) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-egress-timestamp-context-write"
        category: "context-surface"
        tags: [cgroup-skb context writable timestamp egress]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.tstamp + $ctx.hwtstamp + $ctx.priority) | count'
            '  $ctx.tstamp = 123'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-ingress-rejects-tstamp-write"
        category: "context-policy"
        tags: [cgroup-skb context reject writable ingress]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.tstamp = 123'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
    }
    {
        name: "cgroup-skb-ingress-writable-context"
        category: "context-surface"
        tags: [cgroup-skb context writable]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  $ctx.cb.0 = 1'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
