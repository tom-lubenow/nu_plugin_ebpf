const VERIFIER_DIFF_FIXTURES_0469_0500_B = [
    {
        name: "source-helper-tc-egress-skb-metadata-helpers"
        category: "helper-state"
        tags: [helper tc skb metadata egress accept source]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_cgroup_classid" $ctx'
            '  helper-call "bpf_get_route_realm" $ctx'
            '  helper-call "bpf_skb_cgroup_id" $ctx'
            '  helper-call "bpf_skb_ancestor_cgroup_id" $ctx 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-tc-ingress-skb-cgroup-classid"
        category: "helper-state"
        tags: [helper tc skb metadata ingress accept source]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_cgroup_classid" $ctx'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-tc-skb-metadata-rejects-ingress-egress-only"
        category: "helper-state"
        tags: [helper tc skb metadata egress-only reject source]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_route_realm" $ctx'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_route_realm' is only valid in tc/tcx egress programs"
    }
    {
        name: "source-helper-tc-skb-metadata-rejects-xdp"
        category: "helper-state"
        tags: [helper tc skb metadata program-policy reject source]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_cgroup_id" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_cgroup_id' is only valid in tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "source-helper-socket-cookie-accepts-socket-filter-context"
        category: "helper-state"
        tags: [helper socket cookie accept source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-returned-socket-filter-context"
        category: "helper-state"
        tags: [helper socket cookie accept user-function source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  helper-call "bpf_get_socket_cookie" $raw_ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-fentry-socket-arg"
        category: "helper-state"
        tags: [helper socket cookie tracing accept source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx.arg0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-fentry-null"
        category: "helper-state"
        tags: [helper socket cookie tracing "null" accept source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-rejects-fentry-raw-context"
        category: "helper-state"
        tags: [helper socket cookie tracing raw-context reject source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_socket_cookie' arg0 expects socket pointer in fentry programs"
    }
    {
        name: "source-helper-socket-cookie-rejects-socket-filter-null"
        category: "helper-state"
        tags: [helper socket cookie "null" reject source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 46 arg0 expects pointer"
    }
    {
        name: "source-helper-socket-cookie-rejects-sk-lookup"
        category: "helper-state"
        tags: [helper socket cookie program-policy reject source metadata]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_socket_cookie' is only valid"
    }
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
