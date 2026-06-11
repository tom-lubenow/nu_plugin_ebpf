export const VERIFIER_DIFF_FIXTURES_3397_3399 = [
    {
        name: "adjust-packet-sk-skb-parser-room-flags-zero"
        category: "language-surface"
        tags: [adjust-packet sk-skb-parser flags accept]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0 --flags 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-parser-room-rejects-nonzero-mode"
        category: "language-surface"
        tags: [adjust-packet sk-skb-parser flags reject]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 1 --flags 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires arg2 mode = 0 in sk_skb_parser programs"
    }
    {
        name: "adjust-packet-sk-skb-parser-room-rejects-nonzero-flags"
        category: "language-surface"
        tags: [adjust-packet sk-skb-parser flags reject]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0 --flags 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires arg3 flags = 0 in sk_skb_parser programs"
    }
]
