const VERIFIER_DIFF_FIXTURES_2251_2284_B = [
    {
        name: "redirect-socket-sk-msg-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockmap]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockhash]
        target: "sk_msg:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-msg sockmap flags reject source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_redirect_map" $ctx peers 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "msg-redirect-hash-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-msg sockhash flags reject source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "map-put-sock-ops-sockmap"
        category: "language-surface"
        tags: [maps map-put sock-ops sockmap]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockmap $ctx.remote_port --kind sockmap --flags 2'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-sock-ops-sockhash"
        category: "language-surface"
        tags: [maps map-put sock-ops sockhash]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockhash $ctx.remote_port --kind sockhash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
