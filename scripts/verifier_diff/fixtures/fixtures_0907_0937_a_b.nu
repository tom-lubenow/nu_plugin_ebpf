const VERIFIER_DIFF_FIXTURES_0907_0937_A_B = [
    {
        name: "source-helper-getsockopt-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_getsockopt" $ctx 1 2 $optval 8'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-setsockopt-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_setsockopt" $ctx 1 2 $optval 8'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-getsockopt-rejects-non-socket-option-context"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_getsockopt" $ctx 1 2 $optval 8'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_getsockopt' is only valid in sock_ops, cgroup_sock_addr, and cgroup_sockopt programs"
    }
]
