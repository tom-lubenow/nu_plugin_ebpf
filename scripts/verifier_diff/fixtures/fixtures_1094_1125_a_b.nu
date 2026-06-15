const VERIFIER_DIFF_FIXTURES_1094_1125_A_B = [
    {
        name: "iter-bpf-prog-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-prog-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { $ctx.prog.len | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-link-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-link-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { $ctx.link.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
