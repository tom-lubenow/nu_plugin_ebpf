export const VERIFIER_DIFF_FIXTURES_3391_3396 = [
    {
        name: "adjust-packet-tc-action-room-flags-zero"
        category: "language-surface"
        tags: [adjust-packet tc-action flags accept]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0 --flags 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-tc-action-room-rejects-invalid-flags"
        category: "language-surface"
        tags: [adjust-packet tc-action flags reject]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0 --flags 1048576'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires arg3 flags to contain only modeled BPF_F_ADJ_ROOM_* bits"
    }
    {
        name: "adjust-packet-tc-action-room-rejects-incompatible-flags"
        category: "language-surface"
        tags: [adjust-packet tc-action flags reject]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0 --flags 6'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires at most one BPF_F_ADJ_ROOM_ENCAP_L3_* flag"
    }
    {
        name: "adjust-packet-sk-skb-room-flags-zero"
        category: "language-surface"
        tags: [adjust-packet sk-skb flags accept]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0 --flags 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-room-rejects-nonzero-mode"
        category: "language-surface"
        tags: [adjust-packet sk-skb flags reject]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 1 --flags 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires arg2 mode = 0 in sk_skb programs"
    }
    {
        name: "adjust-packet-sk-skb-room-rejects-nonzero-flags"
        category: "language-surface"
        tags: [adjust-packet sk-skb flags reject]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0 --flags 1'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires arg3 flags = 0 in sk_skb programs"
    }
]
