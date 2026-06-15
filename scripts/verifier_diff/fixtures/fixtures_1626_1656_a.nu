const VERIFIER_DIFF_FIXTURES_1626_1656_A = [
    {
        name: "csum-diff-rejects-null-dynamic-side"
        category: "helper-state"
        tags: [csum null-pointer dynamic reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let size = ((helper-call "bpf_get_prandom_u32") + 4)'
            '  helper-call "bpf_csum_diff" 0 $size 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 28 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "csum-diff-rejects-unaligned-size"
        category: "helper-state"
        tags: [csum scalar-policy reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 2 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
    }
    {
        name: "csum-diff-rejects-dynamic-unaligned-size"
        category: "helper-state"
        tags: [csum scalar-policy dynamic branch reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let size = (if $selector == 0 { 0 } else { 2 })'
            '  helper-call "bpf_csum_diff" 0 $size 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
    }
    {
        name: "redirect-neigh-allows-null-params"
        category: "helper-state"
        tags: [redirect-neigh null-pointer tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 0 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-neigh-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-neigh flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_neigh" 1 0 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg3 = 0"
    }
    {
        name: "redirect-neigh-rejects-null-nonzero-plen"
        category: "helper-state"
        tags: [redirect-neigh null-pointer reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 4 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null"
    }
    {
        name: "redirect-neigh-rejects-null-dynamic-plen"
        category: "helper-state"
        tags: [redirect-neigh null-pointer dynamic reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let plen = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_neigh" 1 0 $plen 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null"
    }
]
