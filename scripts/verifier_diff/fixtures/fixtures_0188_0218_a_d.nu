const VERIFIER_DIFF_FIXTURES_0188_0218_A_D = [
    {
        name: "lsm-cgroup-context"
        category: "tracing"
        tags: [lsm-cgroup context]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg2 + $ctx.arg_count + $ctx.pid) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg_count is only available on BTF-backed tracing contexts with bpf_get_func_arg_cnt support"
    }
    {
        name: "lsm-cgroup-named-arg-context"
        category: "tracing"
        tags: [lsm-cgroup context named-arg source metadata]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg.address.sa_family + $ctx.arg.addrlen) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-cgroup-live-target-named-arg-context"
        category: "tracing"
        tags: [lsm-cgroup context named-arg cgroup-path source metadata]
        requires: [kernel-btf]
        target: "lsm_cgroup:/sys/fs/cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg.address.sa_family + $ctx.arg.addrlen) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
