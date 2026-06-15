const VERIFIER_DIFF_FIXTURES_0907_0937_B = [
    {
        name: "cgroup-sockopt-get-optlen-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-get-rejects-level-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.level is only writable on cgroup_sockopt:set hooks"
    }
    {
        name: "cgroup-sockopt-get-rejects-optname-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optname = 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.optname is only writable on cgroup_sockopt:set hooks"
    }
    {
        name: "cgroup-sockopt-rejects-optval-write-without-index"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval = 42'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a fixed index"
    }
    {
        name: "cgroup-sockopt-set-rejects-retval-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup_sockopt:get"
    }
    {
        name: "cgroup-sockopt-set-rejects-retval-read"
        category: "context-policy"
        tags: [cgroup-sockopt reject context]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup_sockopt:get"
    }
    {
        name: "cgroup-sockopt-rejects-optval-write-on-packet-context"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.0 = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.optval is only available on cgroup_sockopt programs"
    }
]
