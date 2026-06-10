const VERIFIER_DIFF_FIXTURES_0813_0843 = [
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
    {
        name: "cgroup-sock-create-context-write"
        category: "context-surface"
        tags: [cgroup-sock context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.sock_type + $ctx.protocol + $ctx.state + $ctx.rx_queue_mapping + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-release-context-write"
        category: "context-surface"
        tags: [cgroup-sock context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_release"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-post-bind6-context"
        category: "context-surface"
        tags: [cgroup-sock context ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind6"
        program: [
            '{|ctx|'
            '  (($ctx.local_ip6 | get 1) + ($ctx.sk.local_ip6 | get 1) + $ctx.local_port + $ctx.sk.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-socket-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sock context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-rejects-post-bind-mark-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-post-bind-bound-dev-if-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.bound_dev_if = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.bound_dev_if is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-post-bind-priority-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.priority is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-create-local-ip4"
        category: "context-policy"
        tags: [cgroup-sock reject]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  $ctx.local_ip4 | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.local_ip4 is only available on cgroup_sock post_bind4"
    }
    {
        name: "cgroup-sock-rejects-post-bind4-src-ip6"
        category: "context-policy"
        tags: [cgroup-sock reject ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sk.src_ip6 | get 0) | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk.src_ip6 is only available on cgroup_sock post_bind6 hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-local-port"
        category: "context-policy"
        tags: [cgroup-sock-addr reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  $ctx.local_port | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.local_port is only available on cgroup_sock_addr bind4/bind6 and getsockname4/getsockname6 hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-local-ip4-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6"
    }
    {
        name: "cgroup-sock-addr-rejects-connect6-user-ip4-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable ipv4]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_ip4 is only available on IPv4 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-user-ip6-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_ip6.0 = 42'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_ip6 is only available on IPv6 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-unix-remote-port-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable unix]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.remote_port is only available on IPv4/IPv6 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-user-family-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_family = 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_family is read-only"
    }
    {
        name: "cgroup-sock-addr-connect4-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.user_ip4 + $ctx.user_port + $ctx.remote_ip4 + $ctx.remote_port + $ctx.sk.family) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-socket-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect4-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  $ctx.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect4-alias-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.remote_ip4 = 2130706433'
            '  $event.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect6-indexed-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect6"
        program: [
            '{|ctx|'
            '  (($ctx.user_ip6 | get 3) + ($ctx.remote_ip6 | get 3) + $ctx.user_port + $ctx.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getpeername4-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getsockname6-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getsockname6-alias-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-sendmsg6-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.msg_src_ip6.3 = 42'
            '  $ctx.local_ip6.2 = 24'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
