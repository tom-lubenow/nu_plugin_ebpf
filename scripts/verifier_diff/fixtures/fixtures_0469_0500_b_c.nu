const VERIFIER_DIFF_FIXTURES_0469_0500_B_C = [
    {
        name: "source-helper-socket-uid-accepts-cgroup-skb"
        category: "helper-state"
        tags: [helper socket uid cgroup-skb accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_uid" $ctx'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-uid-accepts-tc"
        category: "helper-state"
        tags: [helper socket uid tc accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_uid" $ctx'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-uid-rejects-xdp"
        category: "helper-state"
        tags: [helper socket uid program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_uid" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_socket_uid' is only valid in socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "source-helper-netns-cookie-accepts-cgroup-sockopt"
        category: "helper-state"
        tags: [helper netns cookie cgroup-sockopt accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_netns_cookie" $ctx'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-netns-cookie-accepts-sk-msg"
        category: "helper-state"
        tags: [helper netns cookie sk-msg accept source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_netns_cookie" $ctx'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
