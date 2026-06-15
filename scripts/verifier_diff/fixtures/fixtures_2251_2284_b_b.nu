const VERIFIER_DIFF_FIXTURES_2251_2284_B_B = [
    {
        name: "adjust-packet-sk-skb-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-pull-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet sk-skb packet-bounds reject]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --pull 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-sk-skb-pull-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet sk-skb packet-bounds accept]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockmap]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockhash]
        target: "sk_skb:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-skb sockmap flags reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sk_redirect_map" $ctx peers 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "sk-redirect-hash-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-skb sockhash flags reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sk_redirect_hash" $ctx hash_peers "peer-a" $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
]
