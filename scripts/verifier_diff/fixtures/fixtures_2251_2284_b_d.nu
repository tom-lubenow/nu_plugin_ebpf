const VERIFIER_DIFF_FIXTURES_2251_2284_B_D = [
    {
        name: "adjust-packet-sk-skb-parser-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb-parser]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-parser-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-skb-parser sockhash]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
