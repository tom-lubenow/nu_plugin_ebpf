const VERIFIER_DIFF_FIXTURES_0938_0968_A = [
    {
        name: "cgroup-skb-bound-listener-helper-pointer"
        category: "context-surface"
        tags: [cgroup-skb context alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sk.listener'
            '  if $listener {'
            '    $listener.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-socket-helper-root-alias-context"
        category: "context-surface"
        tags: [cgroup-skb context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sock.listener'
            '  let full = $ctx.socket.full'
            '  if $listener {'
            '    $listener.family | count'
            '  }'
            '  if $full {'
            '    $full.family | count'
            '  }'
            '  ($ctx.sock.cgroup_id + $ctx.socket.ancestor_cgroup_id.0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-context"
        category: "context-surface"
        tags: [cgroup-device context]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.access_type + $ctx.device_access + $ctx.device_type + $ctx.major + $ctx.minor) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-current-context"
        category: "context-surface"
        tags: [cgroup-device context current]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-rejects-packet-context"
        category: "context-policy"
        tags: [cgroup-device reject context]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.access_type | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.access_type is only available on cgroup_device programs"
    }
    {
        name: "cgroup-device-rejects-major-write"
        category: "context-policy"
        tags: [cgroup-device reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.major = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.major is read-only"
    }
]
