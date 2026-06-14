const VERIFIER_DIFF_FIXTURES_0782_0812_B = [
    {
        name: "tc-ingress-rejects-egress-context"
        category: "context-policy"
        tags: [tc context reject egress-only]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc/tcx egress programs"
    }
    {
        name: "tcx-ingress-skb-context-write"
        category: "context-surface"
        tags: [tcx context packet writable]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.3 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "next"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-ingress-context-socket-write"
        category: "context-surface"
        tags: [tcx context writable socket]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "next"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-egress-helper-backed-context"
        category: "context-surface"
        tags: [tcx context helper-backed egress]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  ($ctx.skb_cgroup_id + $ctx.skb_ancestor_cgroup_id.0 + $ctx.route_realm + $ctx.cgroup_classid + $ctx.netns_cookie) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-ingress-rejects-egress-context"
        category: "context-policy"
        tags: [tcx context reject egress-only]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  "next"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc/tcx egress programs"
    }
    {
        name: "tcx-egress-rejects-context-socket-write"
        category: "context-policy"
        tags: [tcx context writable socket reject egress-only]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs"
    }
    {
        name: "netkit-primary-skb-context-write"
        category: "context-surface"
        tags: [netkit context packet writable]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.3 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-rejects-context-socket-write"
        category: "context-policy"
        tags: [netkit context writable socket reject]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' is only valid in tc_action, tc, tcx, and sk_lookup programs"
    }
    {
        name: "netkit-peer-skb-context"
        category: "context-surface"
        tags: [netkit context packet]
        requires: [loopback-interface]
        target: "netkit:lo:peer"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.ingress_ifindex + $ctx.queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-rejects-egress-context"
        category: "context-policy"
        tags: [netkit context reject egress-only]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc_action, tc:egress, and tcx:egress programs"
    }
    {
        name: "xdp-rejects-pid-context"
        category: "context-policy"
        tags: [xdp reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on xdp programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-interface"
        category: "context-policy"
        tags: [xdp reject devmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-cpumap"
        category: "context-policy"
        tags: [xdp reject cpumap devmap]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "socket-filter-rejects-direct-data"
        category: "context-policy"
        tags: [socket-filter reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  $ctx.data | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data is not available on socket_filter programs"
    }
    {
        name: "socket-filter-tcp6-context"
        category: "context-surface"
        tags: [socket-filter context ipv6]
        target: "socket_filter:tcp6:[::1]:8080"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "socket-filter-rich-skb-context"
        category: "context-surface"
        tags: [socket-filter context packet source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.ingress_ifindex + $ctx.pkt_type + $ctx.queue_mapping + $ctx.protocol + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.tc_index + $ctx.hash + $ctx.mark + $ctx.priority) | count'
            '  ($ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.0) | count'
            '  "keep"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
