const VERIFIER_DIFF_FIXTURES_0813_0843_A_C = [
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
]
