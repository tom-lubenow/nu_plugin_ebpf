const VERIFIER_DIFF_FIXTURES_0813_0843_B_B = [
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
