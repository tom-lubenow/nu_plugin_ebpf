export const VERIFIER_DIFF_FIXTURES_3400_3404 = [
    {
        name: "map-put-sock-ops-sockmap-flags-zero"
        category: "language-surface"
        tags: [maps map-put sock-ops sockmap flags accept]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockmap $ctx.remote_port --kind sockmap --flags 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-sock-ops-sockmap-rejects-invalid-flags"
        category: "language-surface"
        tags: [maps map-put sock-ops sockmap flags reject]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockmap $ctx.remote_port --kind sockmap --flags 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags to be BPF_ANY, BPF_NOEXIST, or BPF_EXIST"
    }
    {
        name: "map-put-sock-ops-sockhash-flags-noexist"
        category: "language-surface"
        tags: [maps map-put sock-ops sockhash flags accept]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockhash $ctx.remote_port --kind sockhash --flags 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-sock-ops-sockhash-flags-exist"
        category: "language-surface"
        tags: [maps map-put sock-ops sockhash flags accept]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockhash $ctx.remote_port --kind sockhash --flags 2'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-sock-ops-sockhash-rejects-invalid-flags"
        category: "language-surface"
        tags: [maps map-put sock-ops sockhash flags reject]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockhash $ctx.remote_port --kind sockhash --flags 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags to be BPF_ANY, BPF_NOEXIST, or BPF_EXIST"
    }
]
