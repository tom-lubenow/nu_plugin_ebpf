const VERIFIER_DIFF_FIXTURES_0813_0843_B = [
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
]
