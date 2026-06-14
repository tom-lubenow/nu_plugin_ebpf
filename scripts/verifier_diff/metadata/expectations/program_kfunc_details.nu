const PROGRAM_KFUNC_KERNEL_FEATURE_DETAIL_EXPECTATIONS = [
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        feature: {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.4"
            source: "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c"
        }
    }
    {
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.arg0 0 $d'
            '  0'
            '}'
        ]
        feature: {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.12"
            source: "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c"
        }
    }
]
