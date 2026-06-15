const VERIFIER_DIFF_FIXTURES_1626_1656_A_B = [
    {
        name: "redirect-peer-helper"
        category: "helper-state"
        tags: [redirect-peer tc-action accept source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_peer" 1 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-peer-rejects-nonzero-flags"
        category: "helper-state"
        tags: [redirect-peer flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_peer" 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' requires arg1 = 0"
    }
    {
        name: "redirect-helper-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect flags reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect" 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect' requires arg1 flags to contain only BPF_F_INGRESS"
    }
    {
        name: "clone-redirect-rejects-dynamic-flags"
        category: "helper-state"
        tags: [clone-redirect flags reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_clone_redirect" $ctx 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-map flags reject xdp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_map" tx_ports 0 $flags --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_map' requires arg2 flags"
    }
    {
        name: "redirect-peer-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-peer flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_peer" 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' requires arg1 = 0"
    }
]
